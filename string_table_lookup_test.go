package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
)

const lookupTestFile = "internal/testdata/gcc-amd64-darwin-exec.base64"

// tableLookup reads its own copy of the string table at the (offset, size)
// NewFile passes, and records the table size and every offset NewFile asks for.
type tableLookup struct {
	size    uint64
	offsets []uint64
}

func (l *tableLookup) lookup(ra io.ReaderAt) func(int64, uint64) (func(uint64) string, error) {
	return func(offset int64, size uint64) (func(uint64) string, error) {
		tab := make([]byte, size)
		if _, err := ra.ReadAt(tab, offset); err != nil {
			return nil, err
		}
		l.size = size
		return func(off uint64) string {
			l.offsets = append(l.offsets, off)
			return cstring(tab[off:])
		}, nil
	}
}

func TestStringTableLookup(t *testing.T) {
	want, err := openObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	if want.Symtab == nil || len(want.Symtab.Syms) == 0 {
		t.Fatal("fixture has no symbols")
	}

	ra, err := readerAtFromObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	var l tableLookup
	got, err := NewFile(ra, FileConfig{StringTableLookup: l.lookup(ra)})
	if err != nil {
		t.Fatalf("NewFile with StringTableLookup: %v", err)
	}
	if !reflect.DeepEqual(got.Symtab.Syms, want.Symtab.Syms) {
		t.Errorf("symbols differ with StringTableLookup\n got %+v\nwant %+v", got.Symtab.Syms, want.Symtab.Syms)
	}
	if len(l.offsets) == 0 {
		t.Fatal("lookup was never called")
	}
	for _, off := range l.offsets {
		if off >= l.size {
			t.Errorf("NewFile asked for offset %#x, outside Strsize=%#x", off, l.size)
		}
	}
}

func TestStringTableLookupRejectsOverlongName(t *testing.T) {
	ra, err := readerAtFromObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	// One byte longer than the whole table, so the name is overlong even at
	// offset 0 and the test does not depend on where the fixture's symbols sit.
	overlong := func(offset int64, size uint64) (func(uint64) string, error) {
		return func(off uint64) string { return strings.Repeat("x", int(size)+1) }, nil
	}
	_, err = NewFile(ra, FileConfig{StringTableLookup: overlong})
	if err == nil {
		t.Fatal("NewFile accepted a name extending past the string table")
	}
	var fe *FormatError
	if !errors.As(err, &fe) || !strings.Contains(fe.msg, "extends past Strsize") {
		t.Fatalf("error does not wrap the overlong-name FormatError: %v", err)
	}
}

func TestStringTableLookupDeclines(t *testing.T) {
	want, err := openObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	ra, err := readerAtFromObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	declines := func(int64, uint64) (func(uint64) string, error) { return nil, nil }
	got, err := NewFile(ra, FileConfig{StringTableLookup: declines})
	if err != nil {
		t.Fatalf("NewFile with declining StringTableLookup: %v", err)
	}
	if !reflect.DeepEqual(got.Symtab.Syms, want.Symtab.Syms) {
		t.Errorf("symbols differ when the lookup declines\n got %+v\nwant %+v", got.Symtab.Syms, want.Symtab.Syms)
	}
}

func TestStringTableLookupError(t *testing.T) {
	ra, err := readerAtFromObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	failing := func(int64, uint64) (func(uint64) string, error) { return nil, boom }
	_, err = NewFile(ra, FileConfig{StringTableLookup: failing})
	if err == nil {
		t.Fatal("NewFile ignored StringTableLookup error")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("error does not wrap the lookup's error: %v", err)
	}
}

// symtabOnlyMachO builds a little-endian Mach-O whose only load command is
// LC_SYMTAB, so a test controls every n_strx, n_type and n_value and the
// exact bytes of the string table.
func symtabOnlyMachO(is64 bool, strtab string, syms []types.Nlist64) []byte {
	bo := binary.LittleEndian
	hdrSize, nlistSize := types.FileHeaderSize32, 12
	magic, cpu := types.Magic32, types.CPUI386
	if is64 {
		hdrSize, nlistSize = types.FileHeaderSize64, 16
		magic, cpu = types.Magic64, types.CPUAmd64
	}
	const symtabCmdSize = 24
	symoff := hdrSize + symtabCmdSize
	stroff := symoff + len(syms)*nlistSize
	buf := make([]byte, stroff+len(strtab))
	bo.PutUint32(buf[0:], uint32(magic))
	bo.PutUint32(buf[4:], uint32(cpu))
	bo.PutUint32(buf[12:], uint32(types.MH_OBJECT))
	bo.PutUint32(buf[16:], 1)
	bo.PutUint32(buf[20:], symtabCmdSize)
	lc := buf[hdrSize:]
	bo.PutUint32(lc[0:], uint32(types.LC_SYMTAB))
	bo.PutUint32(lc[4:], symtabCmdSize)
	bo.PutUint32(lc[8:], uint32(symoff))
	bo.PutUint32(lc[12:], uint32(len(syms)))
	bo.PutUint32(lc[16:], uint32(stroff))
	bo.PutUint32(lc[20:], uint32(len(strtab)))
	for i, s := range syms {
		if is64 {
			s.Put64(buf[symoff+i*nlistSize:], bo)
		} else {
			n32 := types.Nlist32{Nlist: s.Nlist, Value: uint32(s.Value)}
			n32.Put32(buf[symoff+i*nlistSize:], bo)
		}
	}
	copy(buf[stroff:], strtab)
	return buf
}

func nlist(strx uint32, typ types.NType, value uint64) types.Nlist64 {
	return types.Nlist64{Nlist: types.Nlist{Name: strx, Type: typ}, Value: value}
}

// backedLookup serves names from the file's string table followed by extra
// bytes, the way a lookup over a larger mapping (a shared cache string pool)
// would, and fails the test if NewFile asks for an offset at or past Strsize.
func backedLookup(
	t *testing.T, data []byte, extra string, calls *int,
) func(int64, uint64) (func(uint64) string, error) {
	return func(offset int64, size uint64) (func(uint64) string, error) {
		backing := append(append([]byte{}, data[offset:offset+int64(size)]...), extra...)
		return func(off uint64) string {
			*calls++
			if off >= size {
				t.Errorf("nameAt(%#x) called at or past Strsize=%#x", off, size)
				return ""
			}
			return cstring(backing[off:])
		}, nil
	}
}

// Offsets into symtabNamesStrtab. The last name is deliberately unterminated
// and ends exactly at Strsize.
const (
	strxPlain         = 1
	strxGo            = 8
	strxTarget        = 19
	strxGoIndr        = 27
	strxTail          = 39
	symtabNamesStrtab = "\x00_plain\x00_main.main\x00_target\x00_runtime.gc\x00_tail"
)

func TestSymtabNames(t *testing.T) {
	strsize := uint64(len(symtabNamesStrtab))
	syms := []types.Nlist64{
		nlist(strxPlain, types.N_SECT|types.N_EXT, 0x1000),
		nlist(strxGo, types.N_SECT|types.N_EXT, strxPlain), // not N_INDR: n_value is no name
		nlist(strxTarget, types.N_INDR|types.N_EXT, strxGoIndr),
		nlist(strxTail, types.N_UNDF|types.N_EXT, 0),
		nlist(uint32(strsize), types.N_UNDF|types.N_EXT, 0),
		nlist(0xffffffff, types.N_INDR|types.N_EXT, 0xffffffff),
	}
	type want struct{ name, indirect string }
	wants := []want{
		{"_plain", ""},
		{"main.main", ""},
		{"_target", "runtime.gc"},
		{"_tail", ""},
		{"", ""},
		{"", ""},
	}
	for _, is64 := range []bool{true, false} {
		data := symtabOnlyMachO(is64, symtabNamesStrtab, syms)
		for _, withLookup := range []bool{false, true} {
			var calls int
			var cfg []FileConfig
			if withLookup {
				cfg = append(cfg, FileConfig{StringTableLookup: backedLookup(t, data, "", &calls)})
			}
			f, err := NewFile(bytes.NewReader(data), cfg...)
			if err != nil {
				t.Fatalf("64-bit=%v lookup=%v: NewFile: %v", is64, withLookup, err)
			}
			if withLookup && calls == 0 {
				t.Errorf("64-bit=%v: StringTableLookup's nameAt was never called", is64)
			}
			for i, w := range wants {
				got := f.Symtab.Syms[i]
				if got.Name != w.name || got.IndirectName != w.indirect {
					t.Errorf("64-bit=%v lookup=%v sym %d: got (%q, %q), want (%q, %q)",
						is64, withLookup, i, got.Name, got.IndirectName, w.name, w.indirect)
				}
			}
		}
	}
}

func TestSymtabNamesRejectLookupReadingPastStrsize(t *testing.T) {
	const strtab = "\x00_a\x00_tail" // "_tail" is unterminated inside Strsize
	for name, sym := range map[string]types.Nlist64{
		"name":     nlist(4, types.N_UNDF|types.N_EXT, 0),
		"indirect": nlist(1, types.N_INDR|types.N_EXT, 4),
	} {
		data := symtabOnlyMachO(true, strtab, []types.Nlist64{sym})
		var calls int
		lookup := backedLookup(t, data, "junk", &calls)
		_, err := NewFile(bytes.NewReader(data), FileConfig{StringTableLookup: lookup})
		if err == nil {
			t.Errorf("%s: NewFile accepted %q, which runs past Strsize", name, "_tailjunk")
		} else if !strings.Contains(err.Error(), "extends past Strsize") {
			t.Errorf("%s: unexpected error: %v", name, err)
		}
	}
}
