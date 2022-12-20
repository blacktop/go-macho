package types

//go:generate stringer -type=HeaderFileType,HeaderFlag -trimprefix=MH_ -output header_string.go

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// A FileHeader represents a Mach-O file header.
type FileHeader struct {
	Magic        Magic
	CPU          CPU
	SubCPU       CPUSubtype
	Type         HeaderFileType
	NCommands    uint32
	SizeCommands uint32
	Flags        HeaderFlag
	Reserved     uint32
}

func (h *FileHeader) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0:], uint32(h.Magic))
	o.PutUint32(b[4:], uint32(h.CPU))
	o.PutUint32(b[8:], uint32(h.SubCPU))
	o.PutUint32(b[12:], uint32(h.Type))
	o.PutUint32(b[16:], h.NCommands)
	o.PutUint32(b[20:], h.SizeCommands)
	o.PutUint32(b[24:], uint32(h.Flags))
	if h.Magic == Magic32 {
		return 28
	}
	o.PutUint32(b[28:], 0)
	return 32
}

func (h *FileHeader) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	if err := binary.Write(buf, o, h); err != nil {
		return fmt.Errorf("failed to write segment load command data to buffer: %v", err)
	}
	return nil
}

const (
	FileHeaderSize32 = 7 * 4
	FileHeaderSize64 = 8 * 4
)

type Magic uint32

const (
	Magic32  Magic = 0xfeedface
	Magic64  Magic = 0xfeedfacf
	MagicFat Magic = 0xcafebabe
)

var magicStrings = []IntName{
	{uint32(Magic32), "32-bit MachO"},
	{uint32(Magic64), "64-bit MachO"},
	{uint32(MagicFat), "Fat MachO"},
}

func (i Magic) Int() uint32      { return uint32(i) }
func (i Magic) String() string   { return StringName(uint32(i), magicStrings, false) }
func (i Magic) GoString() string { return StringName(uint32(i), magicStrings, true) }

// A HeaderFileType is the Mach-O file type, e.g. an object file, executable, or dynamic library.
type HeaderFileType uint32

const (
	MH_OBJECT      HeaderFileType = 0x1 /* relocatable object file */
	MH_EXECUTE     HeaderFileType = 0x2 /* demand paged executable file */
	MH_FVMLIB      HeaderFileType = 0x3 /* fixed VM shared library file */
	MH_CORE        HeaderFileType = 0x4 /* core file */
	MH_PRELOAD     HeaderFileType = 0x5 /* preloaded executable file */
	MH_DYLIB       HeaderFileType = 0x6 /* dynamically bound shared library */
	MH_DYLINKER    HeaderFileType = 0x7 /* dynamic link editor */
	MH_BUNDLE      HeaderFileType = 0x8 /* dynamically bound bundle file */
	MH_DYLIB_STUB  HeaderFileType = 0x9 /* shared library stub for static linking only, no section contents */
	MH_DSYM        HeaderFileType = 0xa /* companion file with only debug sections */
	MH_KEXT_BUNDLE HeaderFileType = 0xb /* x86_64 kexts */
	MH_FILESET     HeaderFileType = 0xc /* a file composed of other Mach-Os to be run in the same userspace sharing a single linkedit. */
	MH_GPU_EXECUTE HeaderFileType = 0xd /* gpu program */
	MH_GPU_DYLIB   HeaderFileType = 0xe /* gpu support functions */
)

type HeaderFlag uint32

const (
	None                       HeaderFlag = 0x0
	NoUndefs                   HeaderFlag = 0x1
	IncrLink                   HeaderFlag = 0x2
	DyldLink                   HeaderFlag = 0x4
	BindAtLoad                 HeaderFlag = 0x8
	Prebound                   HeaderFlag = 0x10
	SplitSegs                  HeaderFlag = 0x20
	LazyInit                   HeaderFlag = 0x40
	TwoLevel                   HeaderFlag = 0x80
	ForceFlat                  HeaderFlag = 0x100
	NoMultiDefs                HeaderFlag = 0x200
	NoFixPrebinding            HeaderFlag = 0x400
	Prebindable                HeaderFlag = 0x800
	AllModsBound               HeaderFlag = 0x1000
	SubsectionsViaSymbols      HeaderFlag = 0x2000
	Canonical                  HeaderFlag = 0x4000
	WeakDefines                HeaderFlag = 0x8000
	BindsToWeak                HeaderFlag = 0x10000
	AllowStackExecution        HeaderFlag = 0x20000
	RootSafe                   HeaderFlag = 0x40000
	SetuidSafe                 HeaderFlag = 0x80000
	NoReexportedDylibs         HeaderFlag = 0x100000
	PIE                        HeaderFlag = 0x200000
	DeadStrippableDylib        HeaderFlag = 0x400000
	HasTLVDescriptors          HeaderFlag = 0x800000
	NoHeapExecution            HeaderFlag = 0x1000000
	AppExtensionSafe           HeaderFlag = 0x2000000
	NlistOutofsyncWithDyldinfo HeaderFlag = 0x4000000
	SimSupport                 HeaderFlag = 0x8000000
	DylibInCache               HeaderFlag = 0x80000000
)

// GETTERS
func (f HeaderFlag) None() bool {
	return f == 0
}
func (f HeaderFlag) NoUndefs() bool {
	return (f & NoUndefs) != 0
}
func (f HeaderFlag) IncrLink() bool {
	return (f & IncrLink) != 0
}
func (f HeaderFlag) DyldLink() bool {
	return (f & DyldLink) != 0
}
func (f HeaderFlag) BindAtLoad() bool {
	return (f & BindAtLoad) != 0
}
func (f HeaderFlag) Prebound() bool {
	return (f & Prebound) != 0
}
func (f HeaderFlag) SplitSegs() bool {
	return (f & SplitSegs) != 0
}
func (f HeaderFlag) LazyInit() bool {
	return (f & LazyInit) != 0
}
func (f HeaderFlag) TwoLevel() bool {
	return (f & TwoLevel) != 0
}
func (f HeaderFlag) ForceFlat() bool {
	return (f & ForceFlat) != 0
}
func (f HeaderFlag) NoMultiDefs() bool {
	return (f & NoMultiDefs) != 0
}
func (f HeaderFlag) NoFixPrebinding() bool {
	return (f & NoFixPrebinding) != 0
}
func (f HeaderFlag) Prebindable() bool {
	return (f & Prebindable) != 0
}
func (f HeaderFlag) AllModsBound() bool {
	return (f & AllModsBound) != 0
}
func (f HeaderFlag) SubsectionsViaSymbols() bool {
	return (f & SubsectionsViaSymbols) != 0
}
func (f HeaderFlag) Canonical() bool {
	return (f & Canonical) != 0
}
func (f HeaderFlag) WeakDefines() bool {
	return (f & WeakDefines) != 0
}
func (f HeaderFlag) BindsToWeak() bool {
	return (f & BindsToWeak) != 0
}
func (f HeaderFlag) AllowStackExecution() bool {
	return (f & AllowStackExecution) != 0
}
func (f HeaderFlag) RootSafe() bool {
	return (f & RootSafe) != 0
}
func (f HeaderFlag) SetuidSafe() bool {
	return (f & SetuidSafe) != 0
}
func (f HeaderFlag) NoReexportedDylibs() bool {
	return (f & NoReexportedDylibs) != 0
}
func (f HeaderFlag) PIE() bool {
	return (f & PIE) != 0
}
func (f HeaderFlag) DeadStrippableDylib() bool {
	return (f & DeadStrippableDylib) != 0
}
func (f HeaderFlag) HasTLVDescriptors() bool {
	return (f & HasTLVDescriptors) != 0
}
func (f HeaderFlag) NoHeapExecution() bool {
	return (f & NoHeapExecution) != 0
}
func (f HeaderFlag) AppExtensionSafe() bool {
	return (f & AppExtensionSafe) != 0
}
func (f HeaderFlag) NlistOutofsyncWithDyldinfo() bool {
	return (f & NlistOutofsyncWithDyldinfo) != 0
}
func (f HeaderFlag) SimSupport() bool {
	return (f & SimSupport) != 0
}
func (f HeaderFlag) DylibInCache() bool {
	return (f & DylibInCache) != 0
}

// SETTER
func (f *HeaderFlag) Set(flag HeaderFlag, set bool) {
	if set {
		*f = (*f | flag)
	} else {
		*f = (*f ^ flag)
	}
}

// List returns a string array of flag names
func (f HeaderFlag) List() []string {
	var flags []string
	if f.None() {
		flags = append(flags, None.String())
	}
	if f.NoUndefs() {
		flags = append(flags, NoUndefs.String())
	}
	if f.IncrLink() {
		flags = append(flags, IncrLink.String())
	}
	if f.DyldLink() {
		flags = append(flags, DyldLink.String())
	}
	if f.BindAtLoad() {
		flags = append(flags, BindAtLoad.String())
	}
	if f.Prebound() {
		flags = append(flags, Prebound.String())
	}
	if f.SplitSegs() {
		flags = append(flags, SplitSegs.String())
	}
	if f.LazyInit() {
		flags = append(flags, LazyInit.String())
	}
	if f.TwoLevel() {
		flags = append(flags, TwoLevel.String())
	}
	if f.ForceFlat() {
		flags = append(flags, ForceFlat.String())
	}
	if f.NoMultiDefs() {
		flags = append(flags, NoMultiDefs.String())
	}
	if f.NoFixPrebinding() {
		flags = append(flags, NoFixPrebinding.String())
	}
	if f.Prebindable() {
		flags = append(flags, Prebindable.String())
	}
	if f.AllModsBound() {
		flags = append(flags, AllModsBound.String())
	}
	if f.SubsectionsViaSymbols() {
		flags = append(flags, SubsectionsViaSymbols.String())
	}
	if f.Canonical() {
		flags = append(flags, Canonical.String())
	}
	if f.WeakDefines() {
		flags = append(flags, WeakDefines.String())
	}
	if f.BindsToWeak() {
		flags = append(flags, BindsToWeak.String())
	}
	if f.AllowStackExecution() {
		flags = append(flags, AllowStackExecution.String())
	}
	if f.RootSafe() {
		flags = append(flags, RootSafe.String())
	}
	if f.SetuidSafe() {
		flags = append(flags, SetuidSafe.String())
	}
	if f.NoReexportedDylibs() {
		flags = append(flags, NoReexportedDylibs.String())
	}
	if f.PIE() {
		flags = append(flags, PIE.String())
	}
	if f.DeadStrippableDylib() {
		flags = append(flags, DeadStrippableDylib.String())
	}
	if f.HasTLVDescriptors() {
		flags = append(flags, HasTLVDescriptors.String())
	}
	if f.NoHeapExecution() {
		flags = append(flags, NoHeapExecution.String())
	}
	if f.AppExtensionSafe() {
		flags = append(flags, AppExtensionSafe.String())
	}
	if f.NlistOutofsyncWithDyldinfo() {
		flags = append(flags, NlistOutofsyncWithDyldinfo.String())
	}
	if f.SimSupport() {
		flags = append(flags, SimSupport.String())
	}
	if f.DylibInCache() {
		flags = append(flags, DylibInCache.String())
	}
	return flags
}

func (f HeaderFlag) Flags() string {
	return strings.Join(f.List(), ", ")
}

func (h FileHeader) String() string {

	return fmt.Sprintf(
		"Magic         = %s\n"+
			"Type          = %s\n"+
			"CPU           = %s, %s %s\n"+
			"Commands      = %d (Size: %d)\n"+
			"Flags         = %s\n",
		h.Magic,
		h.Type,
		h.CPU, h.SubCPU.String(h.CPU), h.SubCPU.Caps(h.CPU),
		h.NCommands,
		h.SizeCommands,
		h.Flags.Flags(),
	)
}
