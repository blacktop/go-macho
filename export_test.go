package macho

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
)

func TestRestoreFIPSHMAC(t *testing.T) {
	seal := &types.Section{SectionHeader: types.SectionHeader{Name: "__fips_hmacs", Seg: "__TEXT", Offset: 0x20, Size: 32}}
	text := &types.Section{SectionHeader: types.SectionHeader{Name: "__text", Seg: "__TEXT_EXEC", Offset: 0x80, Size: 5}}
	f := &File{FileTOC: FileTOC{Sections: []*types.Section{seal, text}}}
	data := make([]byte, 0x100)
	copy(data[text.Offset:], []byte("hello"))
	if err := f.restoreFIPSHMAC(data); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte{0})
	_, _ = mac.Write([]byte("hello"))
	if got, want := data[seal.Offset:seal.Offset+32], mac.Sum(nil); !bytes.Equal(got, want) {
		t.Fatalf("FIPS HMAC = %x, want %x", got, want)
	}
}

func newReferenceAdjustmentFile() (*File, exportSegMap, []byte) {
	f := newTextSegmentFile(SegmentHeader{
		Addr:   0,
		Memsz:  0xc000,
		Offset: 0,
		Filesz: 0xc000,
	})
	f.vma = &types.VMAddrConverter{VMAddr2Offet: f.getOffset}
	segMap := exportSegMap{{
		Name: "__TEXT",
		Old:  segInfo{VirtStart: 0x100000, VirtEnd: 0x104000},
		New:  segInfo{Start: 0x8000, End: 0xc000, VirtStart: 0x8000, VirtEnd: 0xc000},
	}, {
		Name: "__DATA",
		Old:  segInfo{VirtStart: 0xfe000, VirtEnd: 0x100000},
		New:  segInfo{Start: 0x6000, End: 0x8000, VirtStart: 0x6000, VirtEnd: 0x8000},
	}}
	return f, segMap, make([]byte, 0xc000)
}

func TestAdjustReferencesPreservesARM64InstructionBits(t *testing.T) {
	t.Run("ADRP", func(t *testing.T) {
		f, segMap, data := newReferenceAdjustmentFile()
		const source = 0x10000c
		const target = 0x0fe000
		const original = 0x90ff1501 // ADRP x1, #imm
		binary.LittleEndian.PutUint32(data[0x800c:], original)

		if _, _, _, _, err := f.adjustReferences(segMap, data, nil, []*types.SplitInfoEntry{{
			Kind: types.DYLD_CACHE_ADJ_V2_ARM64_ADRP, SourceVmAddr: source, TargetVmAddr: target,
		}}); err != nil {
			t.Fatal(err)
		}

		got := binary.LittleEndian.Uint32(data[0x800c:])
		const want = 0xd0ffffe1 // ADRP x1, target page 0x6000 from source page 0x8000
		if got != want {
			t.Errorf("ADRP = %#08x, want %#08x", got, want)
		}
	})

	t.Run("BR26", func(t *testing.T) {
		f, segMap, data := newReferenceAdjustmentFile()
		binary.LittleEndian.PutUint32(data[0x8000:], 0x94000000) // BL #0

		if _, _, _, _, err := f.adjustReferences(segMap, data, nil, []*types.SplitInfoEntry{{
			Kind: types.DYLD_CACHE_ADJ_V2_ARM64_BR26, SourceVmAddr: 0x100000, TargetVmAddr: 0x100010,
		}}); err != nil {
			t.Fatal(err)
		}

		if got, want := binary.LittleEndian.Uint32(data[0x8000:]), uint32(0x94000004); got != want {
			t.Errorf("BR26 = %#08x, want %#08x", got, want)
		}
	})
}

func TestAdjustReferencesUsesOFF12TargetForADRPPage(t *testing.T) {
	f, segMap, data := newReferenceAdjustmentFile()
	// The old target page overlaps __DATA, whose non-page-aligned cache start
	// means the exact target lands on the following page after recovery.
	segMap[1].Old = segInfo{VirtStart: 0xfe238, VirtEnd: 0x100000}
	binary.LittleEndian.PutUint32(data[0x8000:], 0x90000000) // ADRP x0
	binary.LittleEndian.PutUint32(data[0x8004:], 0x91000000) // ADD x0, x0, #0

	_, _, _, _, err := f.adjustReferences(segMap, data, nil, []*types.SplitInfoEntry{{
		Kind: types.DYLD_CACHE_ADJ_V2_ARM64_ADRP, SourceVmAddr: 0x100000, TargetVmAddr: 0xff000,
	}, {
		Kind: types.DYLD_CACHE_ADJ_V2_ARM64_OFF12, SourceVmAddr: 0x100004, TargetVmAddr: 0xff9a0, ExtraVmAddr: 0x100000,
	}})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := binary.LittleEndian.Uint32(data[0x8000:]), uint32(0xf0ffffe0); got != want {
		t.Fatalf("ADRP = %#08x, want %#08x (target page 0x7000)", got, want)
	}
}

func TestAdjustReferencesPreservesOFF12WhenLinearTargetLeavesADRPPage(t *testing.T) {
	f, segMap, data := newReferenceAdjustmentFile()
	segMap[1].Old = segInfo{VirtStart: 0xfe238, VirtEnd: 0x100000}
	binary.LittleEndian.PutUint32(data[0x8000:], 0x90000000) // ADRP x0
	binary.LittleEndian.PutUint32(data[0x8004:], 0x91000000) // ADD x0, x0, #0
	binary.LittleEndian.PutUint32(data[0x8008:], 0x91048c21) // ADD x1, x1, #0x123

	_, _, _, _, err := f.adjustReferences(segMap, data, nil, []*types.SplitInfoEntry{
		{Kind: types.DYLD_CACHE_ADJ_V2_ARM64_ADRP, SourceVmAddr: 0x100000, TargetVmAddr: 0xff000},
		// The first consumer selects the recovered ADRP page at 0x7000.
		{Kind: types.DYLD_CACHE_ADJ_V2_ARM64_OFF12, SourceVmAddr: 0x100004, TargetVmAddr: 0xff9a0, ExtraVmAddr: 0x100000},
		// Linear segment remapping puts this target on 0x6000. It cannot be
		// encoded with the recovered ADRP page and its collection offset must
		// therefore be retained.
		{Kind: types.DYLD_CACHE_ADJ_V2_ARM64_OFF12, SourceVmAddr: 0x100008, TargetVmAddr: 0xfe400, ExtraVmAddr: 0x100000},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := binary.LittleEndian.Uint32(data[0x8008:]), uint32(0x91048c21); got != want {
		t.Fatalf("OFF12 = %#08x, want preserved %#08x", got, want)
	}
}

func TestAdjustReferencesPreservesPointerAuthentication(t *testing.T) {
	f, segMap, data := newReferenceAdjustmentFile()
	const source = 0x100000
	const target = 0x200000
	original := fixupchains.NewDyldChainedPtrArm64eAuthRebase(0, target, 0x9439, 1, 2, 7)
	binary.LittleEndian.PutUint64(data[0x8000:], original.Raw())

	binds, _, _, auths, err := f.adjustReferences(segMap, data, []Symbol{{
		Name: "_external", Value: target,
	}}, []*types.SplitInfoEntry{{
		Kind: types.DYLD_CACHE_ADJ_V2_POINTER_64, SourceVmAddr: source, TargetVmAddr: target,
	}})
	if err != nil {
		t.Fatal(err)
	}

	auth, ok := auths[0x8000]
	if !ok {
		t.Fatal("authenticated pointer metadata was not retained")
	}
	if auth.diversity != 0x9439 || auth.addrDiv != 1 || auth.key != 2 {
		t.Fatalf("authentication = %#v, want diversity=0x9439 addrDiv=1 key=2", auth)
	}

	fixups := f.sortFixups(binds, nil, auths)
	if len(fixups) != 1 {
		t.Fatalf("got %d fixups, want 1", len(fixups))
	}
	bind, ok := fixups[0].(fixupchains.DyldChainedPtrArm64eAuthBind)
	if !ok {
		t.Fatalf("fixup type = %T, want authenticated bind", fixups[0])
	}
	if bind.Diversity() != 0x9439 || bind.AddrDiv() != 1 || bind.Key() != 2 {
		t.Fatalf("bind authentication = diversity=%#x addrDiv=%d key=%d", bind.Diversity(), bind.AddrDiv(), bind.Key())
	}

	imports, _ := assignOrdinals(fixups, binds, nil)
	if got := imports[0].LibOrdinal(); got != -2 {
		t.Fatalf("import library ordinal = %d, want -2 (flat namespace)", got)
	}
}

func TestRecordUniqueTargetSymbolRejectsAliases(t *testing.T) {
	symbols := make(map[uint64]Symbol)
	ambiguous := make(map[uint64]struct{})
	recordUniqueTargetSymbol(symbols, ambiguous, 0x1000, Symbol{Name: "_first"})
	recordUniqueTargetSymbol(symbols, ambiguous, 0x1000, Symbol{Name: "_first"})
	if got := symbols[0x1000].Name; got != "_first" {
		t.Fatalf("unique symbol = %q, want _first", got)
	}
	recordUniqueTargetSymbol(symbols, ambiguous, 0x1000, Symbol{Name: "_alias"})
	if _, ok := symbols[0x1000]; ok {
		t.Fatal("aliased target retained a unique symbol")
	}
	if _, ok := ambiguous[0x1000]; !ok {
		t.Fatal("aliased target was not marked ambiguous")
	}
}

func TestAdjustReferencesRoutesInternalWeakBranchThroughStub(t *testing.T) {
	f, segMap, data := newReferenceAdjustmentFile()
	authGOT := &types.Section{SectionHeader: types.SectionHeader{
		Name: "__auth_got", Seg: "__DATA_CONST", Addr: 0x9000, Size: 8,
		Flags: types.NonLazySymbolPointers,
	}}
	authStubs := &types.Section{SectionHeader: types.SectionHeader{
		Name: "__auth_stubs", Seg: "__TEXT_EXEC", Addr: 0xa000, Size: 16,
	}}
	f.Sections = []*types.Section{authGOT, authStubs}
	f.Magic = types.Magic64
	f.Symtab = &Symtab{Syms: []Symbol{{Name: "_weak", Desc: types.WEAK_DEF}}}
	f.Dysymtab = &Dysymtab{IndirectSyms: []uint32{0}}
	binary.LittleEndian.PutUint32(data[0x8000:], 0x94000004) // BL internal weak definition

	binds, _, handled, _, err := f.adjustReferences(segMap, data, nil, []*types.SplitInfoEntry{
		{Kind: types.DYLD_CACHE_ADJ_V2_POINTER_64, SourceVmAddr: 0x101000, TargetVmAddr: 0x100010},
		{Kind: types.DYLD_CACHE_ADJ_V2_ARM64_BR26, SourceVmAddr: 0x100000, TargetVmAddr: 0x100010},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := binds[0x9000].Name; got != "_weak" {
		t.Fatalf("weak pointer bind = %q, want _weak", got)
	}
	if got, want := handled[0x8000], uint64(0xa000); got != want {
		t.Fatalf("weak branch target = %#x, want stub %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[0x8000:]), uint32(0x94000800); got != want {
		t.Fatalf("weak branch = %#08x, want %#08x", got, want)
	}
}

func TestIndirectPointerSymbolDisambiguatesAliases(t *testing.T) {
	section := &types.Section{SectionHeader: types.SectionHeader{
		Name:      "__auth_got",
		Seg:       "__DATA_CONST",
		Addr:      0x5000,
		Size:      0x10,
		Flags:     types.NonLazySymbolPointers,
		Reserved1: 1,
	}}
	f := &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			Sections:   []*types.Section{section},
		},
		Symtab: &Symtab{Syms: []Symbol{
			{Name: "_memcpy", Value: 0x1234},
			{Name: "_memmove", Value: 0x1234},
		}},
		Dysymtab: &Dysymtab{IndirectSyms: []uint32{0, 1, 0}},
	}

	sym, ok := f.indirectPointerSymbol(0x5000)
	if !ok {
		t.Fatal("indirect symbol was not found")
	}
	if sym.Name != "_memmove" {
		t.Fatalf("indirect symbol = %q, want _memmove", sym.Name)
	}
}

func TestAdjustReferencesRestoresInternalWeakLookupBind(t *testing.T) {
	f, segMap, data := newReferenceAdjustmentFile()
	section := &types.Section{SectionHeader: types.SectionHeader{
		Name: "__auth_got", Seg: "__TEXT", Addr: 0x8000, Size: 8,
		Flags: types.NonLazySymbolPointers,
	}}
	symbol := Symbol{
		Name: "_weak", Type: types.N_SECT | types.N_EXT, Sect: 1,
		Desc: types.WEAK_DEF, Value: 0x100010,
	}
	f.Sections = []*types.Section{section}
	f.Symtab = &Symtab{Syms: []Symbol{symbol}}
	f.Dysymtab = &Dysymtab{IndirectSyms: []uint32{0}}

	binds, rebases, _, _, err := f.adjustReferences(segMap, data, []Symbol{symbol}, []*types.SplitInfoEntry{{
		Kind: types.DYLD_CACHE_ADJ_V2_POINTER_64, SourceVmAddr: 0x100000, TargetVmAddr: 0x100010,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := binds[0x8000].Name; got != "_weak" {
		t.Fatalf("bind = %q, want _weak", got)
	}
	if _, ok := rebases[0x8000]; ok {
		t.Fatal("weak lookup pointer was also emitted as a rebase")
	}
	fixups := f.sortFixups(binds, rebases, nil)
	imports, _ := assignOrdinals(fixups, binds, nil)
	if got := imports[0].LibOrdinal(); got != types.BIND_SPECIAL_DYLIB_WEAK_LOOKUP {
		t.Fatalf("import library ordinal = %d, want weak lookup", got)
	}
}

func TestCreateSymtabRemapsDefinedSymbolValues(t *testing.T) {
	f := &File{
		FileTOC: FileTOC{FileHeader: types.FileHeader{Magic: types.Magic64}},
		Symtab: &Symtab{Syms: []Symbol{{
			Name: "_defined", Type: types.N_SECT | types.N_EXT, Sect: 1, Value: 0x1010,
		}, {
			Name: "_undefined", Type: types.N_UNDF | types.N_EXT, Value: 0,
		}}},
	}
	segMap := exportSegMap{{
		Name: "__TEXT",
		Old:  segInfo{VirtStart: 0x1000, VirtEnd: 0x2000},
		New:  segInfo{VirtStart: 0x8000, VirtEnd: 0x9000},
	}}

	_, _, _, data, _, err := f.createSymtab(0, segMap, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(data[8:16]); got != 0x8010 {
		t.Fatalf("defined symbol value = %#x, want 0x8010", got)
	}
	if got := binary.LittleEndian.Uint64(data[24:32]); got != 0 {
		t.Fatalf("undefined symbol value = %#x, want 0", got)
	}
}

func TestAdjustReferencesKeepsVirtualOverrideTarget(t *testing.T) {
	f, segMap, data := newReferenceAdjustmentFile()
	const source = 0x100000
	const cacheTarget = 0x200000
	// The discriminator describes the base-class slot, but the pointer names
	// the derived override stored in that slot.
	original := fixupchains.NewDyldChainedPtrArm64eAuthRebase(0, cacheTarget, 0x9209, 1, 0, 0)
	binary.LittleEndian.PutUint64(data[0x8000:], original.Raw())

	binds, _, _, _, err := f.adjustReferences(segMap, data, []Symbol{
		{Name: "__ZN9IOService8DispatchE5IORPC", Value: cacheTarget},
		{Name: "__ZN15OSMetaClassBase8DispatchE5IORPC", Value: 0x300000},
	}, []*types.SplitInfoEntry{{
		Kind: types.DYLD_CACHE_ADJ_V2_POINTER_64, SourceVmAddr: source, TargetVmAddr: cacheTarget,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := binds[0x8000].Name, "__ZN9IOService8DispatchE5IORPC"; got != want {
		t.Fatalf("override bind = %q, want %q", got, want)
	}
}

func TestOrderFixupsForImportsMatchesLinkerAtomOrder(t *testing.T) {
	authGOT := &types.Section{SectionHeader: types.SectionHeader{
		Name: "__auth_got", Seg: "__DATA_CONST", Addr: 0x8000, Size: 0x100,
		Flags: types.NonLazySymbolPointers,
	}}
	constant := &types.Section{SectionHeader: types.SectionHeader{
		Name: "__const", Seg: "__DATA_CONST", Addr: 0x9000, Size: 0x200,
	}}
	segment := &Segment{
		SegmentHeader: SegmentHeader{Name: "__DATA_CONST", Addr: 0x8000, Memsz: 0x1200},
		sections:      []*types.Section{authGOT, constant},
	}
	f := &File{
		FileTOC: FileTOC{Loads: loads{segment}, Sections: []*types.Section{authGOT, constant}},
		Symtab: &Symtab{Syms: []Symbol{
			{Name: "_atom1", Type: types.N_SECT, Sect: 2, Value: 0x101000},
			{Name: "_atom2", Type: types.N_SECT, Sect: 2, Value: 0x101100},
		}},
	}
	segMap := exportSegMap{{
		Name: "__DATA_CONST",
		Old:  segInfo{VirtStart: 0x100000, VirtEnd: 0x102000},
		New:  segInfo{VirtStart: 0x8000, VirtEnd: 0xa000},
	}}
	bind := func(address uint64, name string) fixupchains.Fixup {
		return fixupchains.DyldChainedPtrArm64eBind{Fixup: address, Import: name}
	}
	fixups := []fixupchains.Fixup{
		bind(0x8000, "_got_a"), bind(0x8008, "_got_b"),
		bind(0x9040, "_atom1_low"), bind(0x9080, "_atom1_high"),
		bind(0x9140, "_atom2_low"), bind(0x9180, "_atom2_high"),
	}

	imports, _ := assignOrdinals(f.orderFixupsForImports(fixups, segMap), nil, nil)
	var got []string
	for _, imp := range imports {
		got = append(got, imp.Name)
	}
	want := []string{"_got_a", "_got_b", "_atom1_high", "_atom1_low", "_atom2_high", "_atom2_low"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("import order = %v, want %v", got, want)
	}
}

func TestOrderFixupsForImportsFindsAnonymousExternalVtables(t *testing.T) {
	constant := &types.Section{SectionHeader: types.SectionHeader{
		Name: "__const", Seg: "__DATA_CONST", Addr: 0x9000, Size: 0x300,
	}}
	segment := &Segment{
		SegmentHeader: SegmentHeader{Name: "__DATA_CONST", Addr: 0x9000, Memsz: 0x1000},
		sections:      []*types.Section{constant},
	}
	f := &File{FileTOC: FileTOC{Loads: loads{segment}, Sections: []*types.Section{constant}}}
	bind := func(address uint64, name string) fixupchains.Fixup {
		return fixupchains.DyldChainedPtrArm64eBind{Fixup: address, Import: name}
	}
	rebase := func(address uint64, diversity uint16) fixupchains.Fixup {
		return fixupchains.NewDyldChainedPtrArm64eAuthRebase(address, 0x1000, diversity, 1, 0, 0)
	}
	fixups := []fixupchains.Fixup{
		bind(0x9008, "_prefix"),
		rebase(0x9020, 0x3771), rebase(0x9028, 0x56b7),
		bind(0x9030, "_vtable1_low"), bind(0x9040, "_vtable1_high"),
		rebase(0x9100, 0x3771), rebase(0x9108, 0x56b7),
		bind(0x9110, "_vtable2_low"), bind(0x9120, "_vtable2_high"),
	}

	imports, _ := assignOrdinals(f.orderFixupsForImports(fixups, nil), nil, nil)
	var got []string
	for _, imp := range imports {
		got = append(got, imp.Name)
	}
	want := []string{"_prefix", "_vtable1_high", "_vtable1_low", "_vtable2_high", "_vtable2_low"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("import order = %v, want %v", got, want)
	}
}

func TestOrderFixupsForImportsSeparatesDataAfterNamedVtable(t *testing.T) {
	constant := &types.Section{SectionHeader: types.SectionHeader{
		Name: "__const", Seg: "__DATA_CONST", Addr: 0x9000, Size: 0x100,
	}}
	segment := &Segment{
		SegmentHeader: SegmentHeader{Name: "__DATA_CONST", Addr: 0x9000, Memsz: 0x1000},
		sections:      []*types.Section{constant},
	}
	f := &File{
		FileTOC: FileTOC{Loads: loads{segment}, Sections: []*types.Section{constant}},
		Symtab: &Symtab{Syms: []Symbol{{
			Name: "__ZTV7Example", Type: types.N_SECT, Sect: 1, Value: 0x100000,
		}}},
	}
	segMap := exportSegMap{{
		Name: "__DATA_CONST",
		Old:  segInfo{VirtStart: 0x100000, VirtEnd: 0x101000},
		New:  segInfo{VirtStart: 0x9000, VirtEnd: 0xa000},
	}}
	bind := func(address uint64, name string) fixupchains.Fixup {
		return fixupchains.DyldChainedPtrArm64eBind{Fixup: address, Import: name}
	}
	authBind := func(address uint64, name string) fixupchains.Fixup {
		return fixupchains.NewDyldChainedPtrArm64eAuthBind(address, 0, 1, 1, 0, 0, name)
	}
	fixups := []fixupchains.Fixup{
		authBind(0x9020, "_vtable_low"), authBind(0x9028, "_vtable_high"),
		bind(0x9040, "_data_low"), bind(0x9048, "_data_high"),
	}

	imports, _ := assignOrdinals(f.orderFixupsForImports(fixups, segMap), nil, nil)
	var got []string
	for _, imp := range imports {
		got = append(got, imp.Name)
	}
	want := []string{"_vtable_high", "_vtable_low", "_data_high", "_data_low"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("import order = %v, want %v", got, want)
	}
}

func TestClearKmodInfoCacheFields(t *testing.T) {
	segment := &Segment{SegmentHeader: SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64,
		Name:    "__DATA",
		Addr:    0x8000,
		Memsz:   0x1000,
		Offset:  0x4000,
		Filesz:  0x1000,
	}}
	f := &File{
		FileTOC: FileTOC{Loads: loads{segment}},
		Symtab: &Symtab{Syms: []Symbol{{
			Name: "_kmod_info", Type: types.N_SECT | types.N_EXT, Sect: 1, Value: 0x1000,
		}}},
	}
	f.vma = &types.VMAddrConverter{VMAddr2Offet: f.getOffset}
	segMap := exportSegMap{{
		Name: "__DATA",
		Old:  segInfo{VirtStart: 0x1000, VirtEnd: 0x2000},
		New:  segInfo{Start: 0x4000, End: 0x5000, VirtStart: 0x8000, VirtEnd: 0x9000},
	}}
	data := make([]byte, 0x5000)
	for i := 0x409c; i < 0x40ac; i++ {
		data[i] = 0xff
	}

	if err := f.clearKmodInfoCacheFields(segMap, data); err != nil {
		t.Fatal(err)
	}
	for i, value := range data[0x409c:0x40ac] {
		if value != 0 {
			t.Fatalf("cache field byte %d = %#x, want zero", i, value)
		}
	}
}

func TestOptimizeLoadCommandsAssignsGrownSectionOffset(t *testing.T) {
	section := &types.Section{SectionHeader: types.SectionHeader{
		Name:   "__auth_stubs",
		Seg:    "__TEXT_EXEC",
		Addr:   0x1200,
		Size:   0x100,
		Offset: 0,
		Flags:  types.SymbolStubs,
	}}
	segment := &Segment{
		SegmentHeader: SegmentHeader{
			LoadCmd: types.LC_SEGMENT_64,
			Name:    "__TEXT_EXEC",
			Addr:    0x1000,
			Memsz:   0x1000,
			Offset:  0x4000,
			Filesz:  0x1000,
			Nsect:   1,
		},
		sections: []*types.Section{section},
	}
	f := &File{FileTOC: FileTOC{Loads: loads{segment}, Sections: []*types.Section{section}}}
	segMap := exportSegMap{{
		Name: "__TEXT_EXEC",
		Old:  segInfo{Start: 0x4000, End: 0x5000, VirtStart: 0x1000, VirtEnd: 0x2000},
		New:  segInfo{Start: 0x8000, End: 0x9000, VirtStart: 0x8000, VirtEnd: 0x9000},
	}}

	newLoads, err := f.optimizeLoadCommands(segMap, true)
	if err != nil {
		t.Fatal(err)
	}
	got := newLoads[0].(*Segment).sections[0].Offset
	if want := uint32(0x8200); got != want {
		t.Fatalf("grown section offset = %#x, want %#x", got, want)
	}
}

func TestPointerAlignPad(t *testing.T) {
	tests := []struct {
		name       string
		currentLen int
		ptrSize    uint64
		want       int
	}{
		{"already aligned 8", 16, 8, 0},
		{"already aligned 4", 12, 4, 0},
		{"off by 1", 1, 8, 7},
		{"off by 4", 4, 8, 4},
		{"off by 7", 7, 8, 1},
		{"zero len", 0, 8, 0},
		{"4-byte align off by 1", 5, 4, 3},
		{"4-byte align off by 3", 7, 4, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pointerAlignPad(tt.currentLen, tt.ptrSize)
			if got != tt.want {
				t.Errorf("pointerAlignPad(%d, %d) = %d, want %d", tt.currentLen, tt.ptrSize, got, tt.want)
			}
			// result should always be aligned
			aligned := (uint64(tt.currentLen) + uint64(got)) % tt.ptrSize
			if aligned != 0 {
				t.Errorf("pointerAlignPad(%d, %d): result %d not aligned (remainder %d)", tt.currentLen, tt.ptrSize, tt.currentLen+got, aligned)
			}
		})
	}
}

func TestPageAlign(t *testing.T) {
	tests := []struct {
		name  string
		off   uint64
		align uint64
		want  uint64
	}{
		{"already aligned", 0x4000, 0x1000, 0x4000},
		{"needs alignment", 0x4001, 0x1000, 0x5000},
		{"zero", 0, 0x1000, 0},
		{"one byte over", 0x1001, 0x1000, 0x2000},
		{"one byte under", 0x0FFF, 0x1000, 0x1000},
		{"16KB align", 0x4001, 0x4000, 0x8000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pageAlign(tt.off, tt.align)
			if got != tt.want {
				t.Errorf("pageAlign(%#x, %#x) = %#x, want %#x", tt.off, tt.align, got, tt.want)
			}
		})
	}
}

func newTextSegmentFile(seg SegmentHeader, sections ...*types.Section) *File {
	seg.LoadCmd = types.LC_SEGMENT_64
	seg.Name = "__TEXT"
	text := &Segment{
		SegmentHeader: seg,
	}
	return &File{
		FileTOC: FileTOC{
			Loads:    loads{text},
			Sections: sections,
		},
	}
}

func newTextSection(addr uint64, offset uint32) *types.Section {
	return &types.Section{
		SectionHeader: types.SectionHeader{
			Name:   "__text",
			Seg:    "__TEXT",
			Addr:   addr,
			Offset: offset,
		},
	}
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

func TestTextSegmentFirstSectionRelOffUsesVMAddrForCachedImages(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x180000000,
			Offset: 0x3f000000,
			Nsect:  1,
		},
		newTextSection(0x180004000, 0x4000),
	)

	got, err := f.textSegmentFirstSectionRelOff(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x4000 {
		t.Errorf("textSegmentFirstSectionRelOff(true) = %#x, want 0x4000", got)
	}
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidCachedAddress(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x180004000,
			Offset: 0x3f000000,
			Nsect:  1,
		},
		newTextSection(0x180000000, 0x4000),
	)

	_, err := f.textSegmentFirstSectionRelOff(true)
	requireErrorContains(t, err, "precedes segment address")
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidFileOffset(t *testing.T) {
	f := newTextSegmentFile(
		SegmentHeader{
			Addr:   0x100000000,
			Offset: 0x8000,
			Nsect:  1,
		},
		newTextSection(0x100001000, 0x1000),
	)

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "precedes segment offset")
}

func TestTextSegmentFirstSectionRelOffRejectsInvalidSectionIndex(t *testing.T) {
	f := newTextSegmentFile(SegmentHeader{
		Addr:      0x100000000,
		Nsect:     1,
		Firstsect: 1,
	})

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "out of range")
}

func TestTextSegmentFirstSectionRelOffRejectsHugeSectionIndex(t *testing.T) {
	f := newTextSegmentFile(SegmentHeader{
		Addr:      0x100000000,
		Nsect:     1,
		Firstsect: ^uint32(0),
	})

	_, err := f.textSegmentFirstSectionRelOff(false)
	requireErrorContains(t, err, "out of range")
}

func TestTextSegmentFirstSectionRelOffNoTextSegment(t *testing.T) {
	f := &File{}

	got, err := f.textSegmentFirstSectionRelOff(false)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("textSegmentFirstSectionRelOff without __TEXT = %#x, want 0", got)
	}
}

func TestTextSegmentWriteStartRejectsOutOfRangeStart(t *testing.T) {
	_, err := textSegmentWriteStart(0x400000000, 0x2000, 0x10000)
	requireErrorContains(t, err, "exceeds segment data length")
}

func TestTextSegmentWriteStartUsesEndOfLoadsWhenLarger(t *testing.T) {
	got, err := textSegmentWriteStart(0x1000, 0x2000, 0x4000)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x2000 {
		t.Errorf("textSegmentWriteStart = %#x, want 0x2000", got)
	}
}

func TestSegMapRemap(t *testing.T) {
	m := exportSegMap{
		{
			Name:       "__TEXT",
			Old:        segInfo{Start: 0x10000, End: 0x14000},
			New:        segInfo{Start: 0, End: 0x4000},
			OrigMemsz:  0x4000,
			OrigFilesz: 0x4000,
		},
		{
			Name:       "__DATA",
			Old:        segInfo{Start: 0x20000, End: 0x22000},
			New:        segInfo{Start: 0x4000, End: 0x6000},
			OrigMemsz:  0x3000, // bss makes memsz > filesz
			OrigFilesz: 0x2000,
		},
		{
			Name:       "__LINKEDIT",
			Old:        segInfo{Start: 0x30000, End: 0x34000},
			New:        segInfo{Start: 0x6000, End: 0xA000},
			OrigMemsz:  0x4000,
			OrigFilesz: 0x4000,
		},
	}

	// test Remap
	t.Run("remap __TEXT start", func(t *testing.T) {
		got, err := m.RemapOffset(0x10000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0 {
			t.Errorf("Remap(0x10000) = %#x, want 0x0", got)
		}
	})
	t.Run("remap __TEXT middle", func(t *testing.T) {
		got, err := m.RemapOffset(0x12000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0x2000 {
			t.Errorf("Remap(0x12000) = %#x, want 0x2000", got)
		}
	})
	t.Run("remap __DATA start", func(t *testing.T) {
		got, err := m.RemapOffset(0x20000)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0x4000 {
			t.Errorf("Remap(0x20000) = %#x, want 0x4000", got)
		}
	})
	t.Run("remap out of range", func(t *testing.T) {
		_, err := m.RemapOffset(0x50000)
		if err == nil {
			t.Error("Remap(0x50000) should fail for out-of-range offset")
		}
	})

	// test RemapSeg
	t.Run("remap segment __DATA", func(t *testing.T) {
		off, sz, err := m.RemapSeg("__DATA", 0x20000)
		if err != nil {
			t.Fatal(err)
		}
		if off != 0x4000 {
			t.Errorf("RemapSeg offset = %#x, want 0x4000", off)
		}
		if sz != 0x2000 {
			t.Errorf("RemapSeg size = %#x, want 0x2000", sz)
		}
	})

	// test Lookup
	t.Run("lookup __DATA preserves OrigMemsz", func(t *testing.T) {
		smi, ok := m.Lookup("__DATA")
		if !ok {
			t.Fatal("Lookup(__DATA) not found")
		}
		if smi.OrigMemsz != 0x3000 {
			t.Errorf("OrigMemsz = %#x, want 0x3000", smi.OrigMemsz)
		}
		if smi.OrigFilesz != 0x2000 {
			t.Errorf("OrigFilesz = %#x, want 0x2000", smi.OrigFilesz)
		}
	})
	t.Run("lookup nonexistent", func(t *testing.T) {
		_, ok := m.Lookup("__BOGUS")
		if ok {
			t.Error("Lookup(__BOGUS) should return false")
		}
	})
}

func newFunctionVariantLoads(fvOff, ffOff uint32) (*FunctionVariants, *FunctionVariantFixups) {
	fv := &FunctionVariants{
		LinkEditData: LinkEditData{
			LinkEditDataCmd: types.LinkEditDataCmd{LoadCmd: types.LC_FUNCTION_VARIANTS, Offset: fvOff, Size: 0x20},
		},
	}
	ff := &FunctionVariantFixups{
		LinkEditData: LinkEditData{
			LinkEditDataCmd: types.LinkEditDataCmd{LoadCmd: types.LC_FUNCTION_VARIANT_FIXUPS, Offset: ffOff, Size: 0x8},
		},
	}
	return fv, ff
}

func functionVariantSegMap() exportSegMap {
	return exportSegMap{
		{
			Name:       "__LINKEDIT",
			Old:        segInfo{Start: 0x30000, End: 0x40000},
			New:        segInfo{Start: 0x5000, End: 0x15000},
			OrigMemsz:  0x10000,
			OrigFilesz: 0x10000,
		},
	}
}

// On the non-cache path the function-variants linkedit offsets shift with the
// segment, so optimizeLoadCommands must remap them through segMap.
func TestOptimizeLoadCommandsRemapsFunctionVariants(t *testing.T) {
	fv, ff := newFunctionVariantLoads(0x31000, 0x31100)
	f := &File{FileTOC: FileTOC{Loads: loads{fv, ff}}}

	loads, err := f.optimizeLoadCommands(functionVariantSegMap(), false)
	if err != nil {
		t.Fatal(err)
	}
	fv = loads[0].(*FunctionVariants)
	ff = loads[1].(*FunctionVariantFixups)
	// new = New.Start + (off - Old.Start)
	if fv.Offset != 0x6000 {
		t.Errorf("FunctionVariants.Offset = %#x, want 0x6000", fv.Offset)
	}
	if ff.Offset != 0x6100 {
		t.Errorf("FunctionVariantFixups.Offset = %#x, want 0x6100", ff.Offset)
	}
}

// On the in-cache path optimizeLinkedit rewrites the offsets after copying the
// blobs into the rebuilt __LINKEDIT, so optimizeLoadCommands must leave them be.
func TestOptimizeLoadCommandsLeavesFunctionVariantsInCache(t *testing.T) {
	fv, ff := newFunctionVariantLoads(0x31000, 0x31100)
	f := &File{FileTOC: FileTOC{Loads: loads{fv, ff}}}

	loads, err := f.optimizeLoadCommands(functionVariantSegMap(), true)
	if err != nil {
		t.Fatal(err)
	}
	fv = loads[0].(*FunctionVariants)
	ff = loads[1].(*FunctionVariantFixups)
	if fv.Offset != 0x31000 {
		t.Errorf("FunctionVariants.Offset = %#x, want it unchanged (0x31000)", fv.Offset)
	}
	if ff.Offset != 0x6100 {
		t.Errorf("FunctionVariantFixups.Offset = %#x, want 0x6100", ff.Offset)
	}
}

func TestChainedFixupStartsSplitsOnlyAtUnrepresentableGaps(t *testing.T) {
	fixups := []fixupchains.Fixup{
		fixupchains.DyldChainedPtrArm64eRebase{Fixup: 0x1000},
		fixupchains.DyldChainedPtrArm64eRebase{Fixup: 0x1000 + arm64eMaxNext*arm64eKernelStride},
		fixupchains.DyldChainedPtrArm64eRebase{Fixup: 0x1000 + (2*arm64eMaxNext+1)*arm64eKernelStride},
	}

	starts, err := chainedFixupStarts(fixups)
	if err != nil {
		t.Fatalf("chainedFixupStarts() error = %v", err)
	}
	if len(starts) != 2 {
		t.Fatalf("chainedFixupStarts() returned %d starts, want 2", len(starts))
	}
	if starts[0].Offset() != fixups[0].Offset() || starts[1].Offset() != fixups[2].Offset() {
		t.Fatalf("chainedFixupStarts() = [%#x, %#x], want [%#x, %#x]", starts[0].Offset(), starts[1].Offset(), fixups[0].Offset(), fixups[2].Offset())
	}
}

func TestChainedFixupStartsSplitsAtUnalignedDelta(t *testing.T) {
	fixups := []fixupchains.Fixup{
		fixupchains.DyldChainedPtrArm64eRebase{Fixup: 0x1000},
		fixupchains.DyldChainedPtrArm64eRebase{Fixup: 0x1022},
	}

	starts, err := chainedFixupStarts(fixups)
	if err != nil {
		t.Fatalf("chainedFixupStarts() error = %v", err)
	}
	if len(starts) != len(fixups) {
		t.Fatalf("chainedFixupStarts() returned %d starts, want %d", len(starts), len(fixups))
	}
}

func TestStartsInSegmentPacksPageStartsAfter22ByteHeader(t *testing.T) {
	segment := &Segment{SegmentHeader: SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64,
		Name:    "__DATA",
		Addr:    0x1000,
		Memsz:   0x4000,
	}}
	f := &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{CPU: types.CPUArm64},
			Loads:      loads{segment},
		},
	}
	pages := map[[2]int][]fixupchains.Fixup{
		{0, 0}: {fixupchains.DyldChainedPtrArm64eRebase{Fixup: 0x10b4}},
	}

	starts, err := f.createStartsInSegmentStructure(pages)
	if err != nil {
		t.Fatal(err)
	}
	const recordOffset = 8 // starts-in-image header for one segment
	if got := binary.LittleEndian.Uint16(starts[recordOffset+20:]); got != 1 {
		t.Fatalf("page count = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint16(starts[recordOffset+4:]); got != uint16(chainedFixupsPageSize) {
		t.Fatalf("chain page size = %#x, want %#x", got, chainedFixupsPageSize)
	}
	if got := binary.LittleEndian.Uint16(starts[recordOffset+6:]); got != uint16(fixupchains.DYLD_CHAINED_PTR_ARM64E_KERNEL) {
		t.Fatalf("pointer format = %d, want ARM64E_KERNEL", got)
	}
	if got := binary.LittleEndian.Uint16(starts[recordOffset+22:]); got != 0xb4 {
		t.Fatalf("first page start = %#x, want 0xb4", got)
	}
}

func TestRemapAddressPrefersContainingSegment(t *testing.T) {
	// Cache images pack segments back to back: __LASTDATA_CONST starts exactly
	// where __DATA_CONST ends, but the two move to unrelated places.
	m := exportSegMap{
		{Name: "__DATA_CONST", Old: segInfo{Start: 0x1000, End: 0x2000, VirtStart: 0x101000, VirtEnd: 0x102000}, New: segInfo{Start: 0x10000, End: 0x11000, VirtStart: 0x10000, VirtEnd: 0x11000}},
		{Name: "__LASTDATA_CONST", Old: segInfo{Start: 0x2000, End: 0x3000, VirtStart: 0x102000, VirtEnd: 0x103000}, New: segInfo{Start: 0x50000, End: 0x51000, VirtStart: 0x50000, VirtEnd: 0x51000}},
	}
	if got, err := m.RemapAddress(0x102000); err != nil || got != 0x50000 {
		t.Fatalf("RemapAddress(start of second segment) = %#x, %v; want 0x50000", got, err)
	}
	if got, err := m.RemapAddress(0x103000); err != nil || got != 0x51000 {
		t.Fatalf("RemapAddress(end of last segment) = %#x, %v; want 0x51000", got, err)
	}
	if got, err := m.RemapOffset(0x2000); err != nil || got != 0x50000 {
		t.Fatalf("RemapOffset(start of second segment) = %#x, %v; want 0x50000", got, err)
	}
}

func TestSortFixupsUsesHeaderRelativeRebaseTargets(t *testing.T) {
	const base = 0xfffffe0007004000
	f := newTextSegmentFile(SegmentHeader{Addr: base, Memsz: 0x1000000, Filesz: 0x1000000})
	fixups := f.sortFixups(nil, map[uint64]uint64{
		base + 0x100: base + 0x2ddfb8,
		base + 0x108: base + 0x38210,
	}, map[uint64]chainedFixupAuth{base + 0x100: {diversity: 0xd507}})
	if len(fixups) != 2 {
		t.Fatalf("fixup count = %d, want 2", len(fixups))
	}
	auth, ok := fixups[0].(fixupchains.DyldChainedPtrArm64eAuthRebase)
	if !ok || auth.Target() != 0x2ddfb8 {
		t.Fatalf("auth rebase = %#v, want target 0x2ddfb8", fixups[0])
	}
	rebase := fixupchains.NewDyldChainedPtrArm64eRebase(base+0x108, fixups[1].(fixupchains.DyldChainedPtrArm64eRebase).Pointer, 0)
	if rebase.Target() != 0x38210 || rebase.High8() != 0 {
		t.Fatalf("rebase target = %#x high8 = %#x, want 0x38210 and 0", rebase.Target(), rebase.High8())
	}
}

func TestFinalSplitInfoReferencesDescribeExportedImage(t *testing.T) {
	f, segMap, data := newReferenceAdjustmentFile()
	binary.LittleEndian.PutUint32(data[0x8104:], 0x91000000|0x20<<10) // ADD x0, x0, #0x20
	refs := []*types.SplitInfoEntry{
		{Kind: types.DYLD_CACHE_ADJ_V2_POINTER_64, SourceVmAddr: 0x100000, TargetVmAddr: 0xfffffe0000001000}, // became a bind
		{Kind: types.DYLD_CACHE_ADJ_V2_POINTER_64, SourceVmAddr: 0x100008, TargetVmAddr: 0x100200},           // rebase
		{Kind: types.DYLD_CACHE_ADJ_V2_ARM64_BR26, SourceVmAddr: 0x100010, TargetVmAddr: 0xfffffe0000002000}, // external call via stub
		{Kind: types.DYLD_CACHE_ADJ_V2_ARM64_BR26, SourceVmAddr: 0x100014, TargetVmAddr: 0xfffffe0000003000}, // unresolved external
		{Kind: types.DYLD_CACHE_ADJ_V2_ARM64_ADRP, SourceVmAddr: 0x100100, TargetVmAddr: 0xfffffe0000004000}, // cache page
		{Kind: types.DYLD_CACHE_ADJ_V2_ARM64_OFF12, SourceVmAddr: 0x100104, TargetVmAddr: 0x0fe020, ExtraVmAddr: 0x100100},
	}
	binds := map[uint64]Symbol{0x8000: {Name: "_import"}}
	rebases := map[uint64]uint64{0x8008: 0x8200}
	others := map[uint64]uint64{
		0x8010: 0x9000,             // stub
		0x8014: 0xfffffe0000003000, // left untouched
		0x8100: 0x6020,             // exact ADRP target
		0x8104: 0x6020,
	}
	got, err := f.finalSplitInfoReferences(data, segMap, refs, binds, rebases, others, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint64]types.SplitInfoEntry{
		0x8008: {Kind: types.DYLD_CACHE_ADJ_V2_POINTER_64, SourceVmAddr: 0x8008, TargetVmAddr: 0x8200},
		0x8010: {Kind: types.DYLD_CACHE_ADJ_V2_ARM64_BR26, SourceVmAddr: 0x8010, TargetVmAddr: 0x9000},
		0x8100: {Kind: types.DYLD_CACHE_ADJ_V2_ARM64_ADRP, SourceVmAddr: 0x8100, TargetVmAddr: 0x6020},
		0x8104: {Kind: types.DYLD_CACHE_ADJ_V2_ARM64_OFF12, SourceVmAddr: 0x8104, TargetVmAddr: 0x6020},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d references, want %d: %+v", len(got), len(want), got)
	}
	for _, ref := range got {
		if w, ok := want[ref.SourceVmAddr]; !ok || *ref != w {
			t.Errorf("reference %+v, want %+v", *ref, w)
		}
	}
}

func TestSplitInfoSectionLocationUsesEmptySectionAtTarget(t *testing.T) {
	f := &File{}
	sections := []types.Section{{},
		{SectionHeader: types.SectionHeader{Seg: "__LAST", Name: "__pinst", Addr: 0x4000, Size: 8}},
		{SectionHeader: types.SectionHeader{Seg: "__LAST", Name: "__last", Addr: 0x4008, Size: 0}},
	}
	if idx, off, ok := f.splitInfoSectionLocation(sections, 0x4008, true); !ok || idx != 2 || off != 0 {
		t.Fatalf("location = %d+%#x (%v), want __last+0", idx, off, ok)
	}
}

func TestEncodeFunctionStartsUsesExportedBase(t *testing.T) {
	got := encodeFunctionStarts(0, []uint64{0x4000, 0x4060, 0x40b8})
	if want := []byte{0x80, 0x80, 0x01, 0x60, 0x58, 0x00, 0x00, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("function starts = %x, want %x", got, want)
	}
}

func TestAdjustReferencesMovesDeltasLikeCollectionBuilder(t *testing.T) {
	f, _, data := newReferenceAdjustmentFile()
	segMap := exportSegMap{{
		Name: "__TEXT",
		Old:  segInfo{VirtStart: 0x100000, VirtEnd: 0x104000},
		New:  segInfo{Start: 0x8000, End: 0xc000, VirtStart: 0x8000, VirtEnd: 0xc000},
	}, {
		Name: "__DATA",
		Old:  segInfo{VirtStart: 0xfe000, VirtEnd: 0x100000},
		New:  segInfo{Start: 0x2000, End: 0x4000, VirtStart: 0x2000, VirtEnd: 0x4000},
	}}
	// A table entry relative to its table start (not to itself): the value is
	// only adjusted by how far the target moved relative to the source.
	delta := int64(0xfe020 - 0x100000)
	binary.LittleEndian.PutUint64(data[0x8010:], uint64(delta))
	// A backwards delta within one section (eh_frame CIE pointer) is unchanged.
	binary.LittleEndian.PutUint32(data[0x8020:], 0x18)
	if _, _, _, _, err := f.adjustReferences(segMap, data, nil, []*types.SplitInfoEntry{
		{Kind: types.DYLD_CACHE_ADJ_V2_DELTA_64, SourceVmAddr: 0x100010, TargetVmAddr: 0xfe030},
		{Kind: types.DYLD_CACHE_ADJ_V2_DELTA_32, SourceVmAddr: 0x100020, TargetVmAddr: 0x100008},
	}); err != nil {
		t.Fatal(err)
	}
	if got, want := int64(binary.LittleEndian.Uint64(data[0x8010:])), int64(0x2020-0x8000); got != want {
		t.Fatalf("DELTA_64 = %#x, want %#x", got, want)
	}
	if got := binary.LittleEndian.Uint32(data[0x8020:]); got != 0x18 {
		t.Fatalf("DELTA_32 = %#x, want 0x18", got)
	}
}

func TestAssignOrdinalsKeepsWeakImports(t *testing.T) {
	bind, err := fixupchains.NewDyldChainedPtrArm64eBind(0x1000, 0, 0, 0, "_maybe")
	if err != nil {
		t.Fatal(err)
	}
	imports, _ := assignOrdinals([]fixupchains.Fixup{bind}, nil, map[string]bool{"_maybe": true})
	if len(imports) != 1 || !imports[0].WeakImport() || imports[0].LibOrdinal() != -2 {
		t.Fatalf("imports = %+v, want one weak flat-namespace import", imports)
	}
}

func TestOrderLoadsLikeLinker(t *testing.T) {
	cmd := func(c types.LoadCmd) Load {
		switch c {
		case types.LC_SEGMENT_64:
			return &Segment{SegmentHeader: SegmentHeader{LoadCmd: c}}
		case types.LC_DYLD_CHAINED_FIXUPS:
			return &DyldChainedFixups{LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{LoadCmd: c}}}
		case types.LC_SEGMENT_SPLIT_INFO:
			return &SplitInfo{SegmentSplitInfoCmd: types.SegmentSplitInfoCmd{LoadCmd: c}}
		case types.LC_FUNCTION_STARTS:
			return &FunctionStarts{LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{LoadCmd: c}}}
		case types.LC_UUID:
			return &UUID{UUIDCmd: types.UUIDCmd{LoadCmd: c}}
		}
		return &UnixThread{Thread: Thread{ThreadCmd: types.ThreadCmd{LoadCmd: c}}}
	}
	loads := []Load{cmd(types.LC_SEGMENT_64), cmd(types.LC_SEGMENT_64), cmd(types.LC_UUID), cmd(types.LC_UNIXTHREAD),
		cmd(types.LC_FUNCTION_STARTS), cmd(types.LC_DYLD_CHAINED_FIXUPS), cmd(types.LC_SEGMENT_SPLIT_INFO)}
	var got []types.LoadCmd
	for _, l := range orderLoadsLikeLinker(loads) {
		got = append(got, l.Command())
	}
	want := []types.LoadCmd{types.LC_SEGMENT_64, types.LC_SEGMENT_64, types.LC_DYLD_CHAINED_FIXUPS, types.LC_UUID,
		types.LC_UNIXTHREAD, types.LC_SEGMENT_SPLIT_INFO, types.LC_FUNCTION_STARTS}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestIndirectSymbolFromBindsUsesBoundImport(t *testing.T) {
	got := &types.Section{SectionHeader: types.SectionHeader{Name: "__got", Seg: "__DATA_CONST", Addr: 0x1000, Size: 16, Reserved1: 2,
		Flags: types.NonLazySymbolPointers}}
	f := &File{FileTOC: FileTOC{Sections: []*types.Section{got}}}
	f.Magic = types.Magic64
	var symtab bytes.Buffer
	strtab := []byte("\x00_a\x00_b\x00")
	binary.Write(&symtab, binary.LittleEndian, types.Nlist64{Nlist: types.Nlist{Name: 1, Type: types.N_UNDF | types.N_EXT}})
	binary.Write(&symtab, binary.LittleEndian, types.Nlist64{Nlist: types.Nlist{Name: 4, Type: types.N_UNDF | types.N_EXT}})
	lookup := f.indirectSymbolFromBinds(symtab.Bytes(), strtab, map[uint64]Symbol{0x1008: {Name: "_a"}})
	if index, ok := lookup(3); !ok || index != 0 {
		t.Fatalf("entry 3 = %d, %v; want _a (0)", index, ok)
	}
	if _, ok := lookup(2); ok {
		t.Fatal("entry 2 has no bind but was resolved")
	}
}

// exportTestSymtab rebuilds f's symbol table with an identity segment map and
// returns its string pool, its nlist entries decoded as Nlist64, and the
// local, external defined and undefined symbol counts.
func exportTestSymtab(t *testing.T, f *File, exports []trie.TrieExport) ([]byte, []types.Nlist64, [3]uint32) {
	t.Helper()
	identity := exportSegMap{{Name: "__TEXT", Old: segInfo{VirtEnd: 1 << 40}, New: segInfo{VirtEnd: 1 << 40}}}
	nLocal, nExtdef, nUndef, symtab, pool, err := f.createSymtab(0, identity, nil, exports)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(symtab)
	var entries []types.Nlist64
	for r.Len() > 0 {
		var got types.Nlist64
		if f.is64bit() {
			err = binary.Read(r, binary.LittleEndian, &got)
		} else {
			var entry types.Nlist32
			err = binary.Read(r, binary.LittleEndian, &entry)
			got = types.Nlist64{Nlist: entry.Nlist, Value: uint64(entry.Value)}
		}
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, got)
	}
	return pool, entries, [3]uint32{nLocal, nExtdef, nUndef}
}

func TestExportIndirectSymbolPool(t *testing.T) {
	for _, magic := range []types.Magic{types.Magic32, types.Magic64} {
		for _, source := range []string{"symtab", "trie"} {
			for _, target := range []string{"_target", ""} {
				t.Run(fmt.Sprintf("%v/%s/target=%q", magic, source, target), func(t *testing.T) {
					indirect := Symbol{Name: "_alias", IndirectName: target, Type: types.N_INDR | types.N_EXT, Value: 0x33b91352}
					section := Symbol{Name: "_section", Type: types.N_SECT, Sect: 1, Desc: 0x20, Value: 0x12345678}
					f := &File{
						FileTOC: FileTOC{FileHeader: types.FileHeader{Magic: magic}, ByteOrder: binary.LittleEndian},
						Symtab:  &Symtab{Syms: []Symbol{indirect, section}},
					}
					var exports []trie.TrieExport
					if source == "trie" {
						f.Symtab.Syms = []Symbol{section}
						exports = []trie.TrieExport{{Name: indirect.Name, ReExport: target, Address: indirect.Value, Flags: types.EXPORT_SYMBOL_FLAGS_REEXPORT}}
					}
					pool, entries, counts := exportTestSymtab(t, f, exports)
					if counts != [3]uint32{1, 1, 0} || len(entries) != 2 {
						t.Fatalf("got %d entries with counts %v, want 2 with [1 1 0]", len(entries), counts)
					}
					wantTarget := target
					if source == "trie" && wantTarget == "" {
						wantTarget = indirect.Name
					}
					// External defined names come first, then local ones.
					wantPool := "\x00\x00\x00\x00_alias\x00"
					if wantTarget != "" {
						wantPool += wantTarget + "\x00"
					}
					sectionName := uint32(len(wantPool))
					wantPool += "_section\x00"
					wantPool += strings.Repeat("\x00", pointerAlignPad(len(wantPool), f.pointerSize()))
					if string(pool) != wantPool {
						t.Fatalf("pool = %q, want %q", pool, wantPool)
					}
					// Entries are in DYSYMTAB order: locals, then external defined.
					wantSection := types.Nlist64{Nlist: types.Nlist{Name: sectionName, Type: section.Type, Sect: section.Sect, Desc: section.Desc}, Value: section.Value}
					if entries[0] != wantSection {
						t.Fatalf("section entry = %+v, want %+v", entries[0], wantSection)
					}
					got := entries[1]
					if wantHeader := (types.Nlist{Name: 4, Type: indirect.Type}); got.Nlist != wantHeader {
						t.Fatalf("indirect entry header = %+v, want %+v", got.Nlist, wantHeader)
					}
					if wantTarget == "" {
						if got.Value != 0 {
							t.Fatalf("unknown target value = %d, want 0", got.Value)
						}
					} else if got.Value != 4+uint64(len(indirect.Name))+1 {
						t.Fatalf("indirect value = %d, want target immediately after symbol name", got.Value)
					} else if name, _, _ := bytes.Cut(pool[got.Value:], []byte{0}); string(name) != wantTarget {
						t.Fatalf("indirect target = %q, want %q", name, wantTarget)
					}
					if source == "symtab" && f.Symtab.Syms[0] != indirect {
						t.Fatal("source indirect symbol was mutated")
					}
				})
			}
		}
		for _, tc := range []struct {
			name       string
			flags      types.ExportFlag
			fromSymtab bool
			wantType   types.NType
		}{
			{name: "absolute", flags: types.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE, wantType: types.N_ABS | types.N_EXT},
			{name: "thread-local", flags: types.EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL},
			{name: "thread-local-with-symtab", flags: types.EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, fromSymtab: true, wantType: types.N_SECT | types.N_EXT},
		} {
			t.Run(fmt.Sprintf("%v/trie/%s", magic, tc.name), func(t *testing.T) {
				f := &File{
					FileTOC: FileTOC{FileHeader: types.FileHeader{Magic: magic}, ByteOrder: binary.LittleEndian},
					Symtab:  &Symtab{},
				}
				want := Symbol{Name: "_export", Type: tc.wantType, Value: 0x12345678}
				if tc.fromSymtab {
					want.Sect, want.Desc, want.Value = 3, 0x20, 0x87654321
					f.Symtab.Syms = []Symbol{want}
				}
				pool, entries, counts := exportTestSymtab(t, f, []trie.TrieExport{{Name: "_export", Address: 0x12345678, Flags: tc.flags}})
				var wantCount uint32
				wantPool := "\x00\x00\x00\x00"
				if tc.wantType != 0 {
					wantCount = 1
					wantPool += want.Name + "\x00"
				}
				if counts != [3]uint32{0, wantCount, 0} || uint32(len(entries)) != wantCount {
					t.Fatalf("got %d entries with counts %v, want %d extdef", len(entries), counts, wantCount)
				}
				wantPool += strings.Repeat("\x00", pointerAlignPad(len(wantPool), f.pointerSize()))
				if string(pool) != wantPool {
					t.Fatalf("pool = %q, want %q", pool, wantPool)
				}
				if wantCount == 0 {
					return
				}
				wantEntry := types.Nlist64{Nlist: types.Nlist{Name: 4, Type: want.Type, Sect: want.Sect, Desc: want.Desc}, Value: want.Value}
				if entries[0] != wantEntry {
					t.Fatalf("entry = %+v, want %+v", entries[0], wantEntry)
				}
				if tc.fromSymtab && f.Symtab.Syms[0] != want {
					t.Fatal("source thread-local symbol was mutated")
				}
			})
		}
	}
}
