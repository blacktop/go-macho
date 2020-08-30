package types

import "fmt"

type DCSymbolsFormat uint32

const (
	DC_SFORMAT_UNCOMPRESSED    DCSymbolsFormat = 0
	DC_SFORMAT_ZLIB_COMPRESSED DCSymbolsFormat = 1
)

type DyldChainedFixups struct {
	DyldChainedFixupsHeader
	DyldChainedStartsInSegment
	Imports []DcfImport
	Rebases []Rebase
	Binds   []Bind
}

type Rebase interface {
	Offset() uint
}

type Bind interface {
	Ordinal() uint
}

type DcfImport struct {
	Name    string
	Pointer interface{}
}

func (i DcfImport) String() string {
	return fmt.Sprintf("%s, %s", i.Pointer, i.Name)
}

// DyldChainedFixupsHeader object is the header of the LC_DYLD_CHAINED_FIXUPS payload
type DyldChainedFixupsHeader struct {
	FixupsVersion uint32          // 0
	StartsOffset  uint32          // offset of DyldChainedStartsInImage in chain_data
	ImportsOffset uint32          // offset of imports table in chain_data
	SymbolsOffset uint32          // offset of symbol strings in chain_data
	ImportsCount  uint32          // number of imported symbol names
	ImportsFormat DCImportsFormat // DYLD_CHAINED_IMPORT*
	SymbolsFormat DCSymbolsFormat // 0 => uncompressed, 1 => zlib compressed
}

// DyldChainedStartsInImage this struct is embedded in LC_DYLD_CHAINED_FIXUPS payload
type DyldChainedStartsInImage struct {
	SegCount       uint32
	SegInfoOffset1 uint32 // []uint32 ARRAY each entry is offset into this struct for that segment
	// followed by pool of dyld_chain_starts_in_segment data
}

// DCPtrKind are values for dyld_chained_starts_in_segment.pointer_format
type DCPtrKind uint16

const (
	DYLD_CHAINED_PTR_ARM64E              DCPtrKind = 1 // stride 8, unauth target is vmaddr
	DYLD_CHAINED_PTR_64                  DCPtrKind = 2 // target is vmaddr
	DYLD_CHAINED_PTR_32                  DCPtrKind = 3
	DYLD_CHAINED_PTR_32_CACHE            DCPtrKind = 4
	DYLD_CHAINED_PTR_32_FIRMWARE         DCPtrKind = 5
	DYLD_CHAINED_PTR_64_OFFSET           DCPtrKind = 6 // target is vm offset
	DYLD_CHAINED_PTR_ARM64E_OFFSET       DCPtrKind = 7 // old name
	DYLD_CHAINED_PTR_ARM64E_KERNEL       DCPtrKind = 7 // stride 4, unauth target is vm offset
	DYLD_CHAINED_PTR_64_KERNEL_CACHE     DCPtrKind = 8
	DYLD_CHAINED_PTR_ARM64E_USERLAND     DCPtrKind = 9  // stride 8, unauth target is vm offset
	DYLD_CHAINED_PTR_ARM64E_FIRMWARE     DCPtrKind = 10 // stride 4, unauth target is vmaddr
	DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE DCPtrKind = 11 // stride 1, x86_64 kernel caches
	DYLD_CHAINED_PTR_ARM64E_USERLAND24   DCPtrKind = 12 // stride 8, unauth target is vm offset, 24-bit bind
)

// DyldChainedStartsInSegment object is embedded in dyld_chain_starts_in_image
// and passed down to the kernel for page-in linking
type DyldChainedStartsInSegment struct {
	Size            uint32    // size of this (amount kernel needs to copy)
	PageSize        uint16    // 0x1000 or 0x4000
	PointerFormat   DCPtrKind // DYLD_CHAINED_PTR_*
	SegmentOffset   uint64    // offset in memory to start of segment
	MaxValidPointer uint32    // for 32-bit OS, any value beyond this is not a pointer
	PageCount       uint16    // how many pages are in array
	// uint16_t    page_start[1]      // each entry is offset in each page of first element in chain
	//                                 // or DYLD_CHAINED_PTR_START_NONE if no fixups on page
	// uint16_t    chain_starts[1];    // some 32-bit formats may require multiple starts per page.
	// for those, if high bit is set in page_starts[], then it
	// is index into chain_starts[] which is a list of starts
	// the last of which has the high bit set
}

type DCPtrStart uint16

const (
	DYLD_CHAINED_PTR_START_NONE  DCPtrStart = 0xFFFF // used in page_start[] to denote a page with no fixups
	DYLD_CHAINED_PTR_START_MULTI DCPtrStart = 0x8000 // used in page_start[] to denote a page which has multiple starts
	DYLD_CHAINED_PTR_START_LAST  DCPtrStart = 0x8000 // used in chain_starts[] to denote last start in list for page
)

func DcpArm64eIsBind(ptr uint64) bool {
	return ExtractBits(ptr, 62, 1) != 0
}

func DcpArm64eIsAuth(ptr uint64) bool {
	return ExtractBits(ptr, 63, 1) != 0
}

func DcpArm64eNext(ptr uint64) uint64 {
	return ExtractBits(uint64(ptr), 51, 11)
}

func Generic64Next(ptr uint64) uint64 {
	return ExtractBits(uint64(ptr), 51, 12)
}
func Generic64IsBind(ptr uint64) bool {
	return ExtractBits(uint64(ptr), 63, 1) != 0
}

func Generic32Next(ptr uint32) uint64 {
	return ExtractBits(uint64(ptr), 26, 5)
}

func Generic32IsBind(ptr uint32) bool {
	return ExtractBits(uint64(ptr), 31, 1) != 0
}

// KeyName returns the chained pointer's key name
func KeyName(keyVal uint64) string {
	name := []string{"IA", "IB", "DA", "DB"}
	key := uint64(keyVal >> 49 & 0x3)
	if key >= 4 {
		return "ERROR"
	}
	return name[key]
}

// DYLD_CHAINED_PTR_ARM64E
type DyldChainedPtrArm64eRebase uint64

func (d DyldChainedPtrArm64eRebase) Target() uint64 {
	return ExtractBits(uint64(d), 0, 43) // runtimeOffset
}
func (d DyldChainedPtrArm64eRebase) High8() uint64 {
	return ExtractBits(uint64(d), 43, 8)
}
func (d DyldChainedPtrArm64eRebase) Offset() uint {
	return uint(d.High8()<<56 | d.Target())
}
func (d DyldChainedPtrArm64eRebase) Next() uint64 {
	return ExtractBits(uint64(d), 51, 11) // 4 or 8-byte stide
}
func (d DyldChainedPtrArm64eRebase) Bind() uint64 {
	return ExtractBits(uint64(d), 62, 1) // == 0
}
func (d DyldChainedPtrArm64eRebase) Auth() uint64 {
	return ExtractBits(uint64(d), 63, 1) // == 0
}
func (d DyldChainedPtrArm64eRebase) String() string {
	return fmt.Sprintf("offset: 0x%016x, next: %d, type: rebase", d.Offset(), d.Next())
}

// DYLD_CHAINED_PTR_ARM64E
type DyldChainedPtrArm64eBind uint64

func (d DyldChainedPtrArm64eBind) Ordinal() uint {
	return uint(ExtractBits(uint64(d), 0, 16))
}
func (d DyldChainedPtrArm64eBind) Zero() uint64 {
	return ExtractBits(uint64(d), 16, 16)
}
func (d DyldChainedPtrArm64eBind) Addend() uint64 {
	return ExtractBits(uint64(d), 32, 19) // +/-256K
}

func (d DyldChainedPtrArm64eBind) SignExtendedAddend() uint64 {
	addend19 := ExtractBits(uint64(d), 32, 19) // +/-256K
	if (addend19 & 0x40000) != 0 {
		return addend19 | 0xFFFFFFFFFFFC0000
	}
	return addend19
}
func (d DyldChainedPtrArm64eBind) Next() uint64 {
	return ExtractBits(uint64(d), 51, 11) // 4 or 8-byte stide
}
func (d DyldChainedPtrArm64eBind) Bind() uint64 {
	return ExtractBits(uint64(d), 62, 1) // == 1
}
func (d DyldChainedPtrArm64eBind) Auth() uint64 {
	return ExtractBits(uint64(d), 63, 1) // == 0
}
func (d DyldChainedPtrArm64eBind) String() string {
	return fmt.Sprintf("ordinal: %d, addend: %x, next: %d, type: bind", d.Ordinal(), d.Addend(), d.Next())
}

// DYLD_CHAINED_PTR_ARM64E
type DyldChainedPtrArm64eAuthRebase uint64

func (d DyldChainedPtrArm64eAuthRebase) Offset() uint {
	return uint(ExtractBits(uint64(d), 0, 32)) // target
}
func (d DyldChainedPtrArm64eAuthRebase) Diversity() uint64 {
	return ExtractBits(uint64(d), 32, 16)
}
func (d DyldChainedPtrArm64eAuthRebase) AddrDiv() uint64 {
	return ExtractBits(uint64(d), 48, 1)
}
func (d DyldChainedPtrArm64eAuthRebase) Key() uint64 {
	return ExtractBits(uint64(d), 49, 2)
}
func (d DyldChainedPtrArm64eAuthRebase) Next() uint64 {
	return ExtractBits(uint64(d), 51, 11) // 4 or 8-byte stide
}
func (d DyldChainedPtrArm64eAuthRebase) Bind() uint64 {
	return ExtractBits(uint64(d), 62, 1) // == 0
}
func (d DyldChainedPtrArm64eAuthRebase) Auth() uint64 {
	return ExtractBits(uint64(d), 63, 1) // == 1
}
func (d DyldChainedPtrArm64eAuthRebase) String() string {
	return fmt.Sprintf("offset: 0x%08x, diversity: %x, has_diversity: %t, key: %s, next: %d, is_auth: %t, type: rebase",
		d.Offset(),
		d.Diversity(),
		d.AddrDiv() == 1,
		KeyName(d.Key()),
		d.Next(),
		d.Auth() == 1)
}

// DYLD_CHAINED_PTR_ARM64E
type DyldChainedPtrArm64eAuthBind uint64

func (d DyldChainedPtrArm64eAuthBind) Ordinal() uint {
	return uint(ExtractBits(uint64(d), 0, 16))
}
func (d DyldChainedPtrArm64eAuthBind) Zero() uint64 {
	return ExtractBits(uint64(d), 16, 16)
}
func (d DyldChainedPtrArm64eAuthBind) Diversity() uint64 {
	return ExtractBits(uint64(d), 32, 16)
}
func (d DyldChainedPtrArm64eAuthBind) AddrDiv() uint64 {
	return ExtractBits(uint64(d), 48, 1)
}
func (d DyldChainedPtrArm64eAuthBind) Key() uint64 {
	return ExtractBits(uint64(d), 49, 2)
}
func (d DyldChainedPtrArm64eAuthBind) Next() uint64 {
	return ExtractBits(uint64(d), 51, 11) // 4 or 8-byte stide
}
func (d DyldChainedPtrArm64eAuthBind) Bind() uint64 {
	return ExtractBits(uint64(d), 62, 1) // == 1
}
func (d DyldChainedPtrArm64eAuthBind) Auth() uint64 {
	return ExtractBits(uint64(d), 63, 1) // == 1
}
func (d DyldChainedPtrArm64eAuthBind) String() string {
	return fmt.Sprintf("ordinal: %d, diversity: %x, has_diversity: %t, key: %s, next: %d, is_auth: %t, type: bind",
		d.Ordinal(),
		d.Diversity(),
		d.AddrDiv() == 1,
		KeyName(d.Key()),
		d.Next(),
		d.Auth() == 1)
}

// DYLD_CHAINED_PTR_64
type DyldChainedPtr64Rebase uint64

func (d DyldChainedPtr64Rebase) Target() uint64 {
	return ExtractBits(uint64(d), 0, 36) // runtimeOffset 64GB max image size
}
func (d DyldChainedPtr64Rebase) High8() uint64 {
	return ExtractBits(uint64(d), 36, 8) // after slide added
}
func (d DyldChainedPtr64Rebase) Offset() uint {
	return uint(d.High8()<<56 | d.Target())
}
func (d DyldChainedPtr64Rebase) Reserved() uint64 {
	return ExtractBits(uint64(d), 44, 7) // all zeros
}
func (d DyldChainedPtr64Rebase) Next() uint64 {
	return ExtractBits(uint64(d), 51, 12) // 4-byte stride
}
func (d DyldChainedPtr64Rebase) Bind() uint64 {
	return ExtractBits(uint64(d), 63, 1) // == 0
}
func (d DyldChainedPtr64Rebase) String() string {
	return fmt.Sprintf("vmaddr: 0x%016x, next: %d", d.Offset(), d.Next())
}

// DYLD_CHAINED_PTR_64_OFFSET
type DyldChainedPtr64RebaseOffset uint64

func (d DyldChainedPtr64RebaseOffset) Target() uint64 {
	return ExtractBits(uint64(d), 0, 36) // vmAddr 64GB max image size
}
func (d DyldChainedPtr64RebaseOffset) High8() uint64 {
	return ExtractBits(uint64(d), 36, 8) // before slide added)
}
func (d DyldChainedPtr64RebaseOffset) Offset() uint {
	return uint(d.High8()<<56 | d.Target())
}
func (d DyldChainedPtr64RebaseOffset) Reserved() uint64 {
	return ExtractBits(uint64(d), 44, 7) // all zeros
}
func (d DyldChainedPtr64RebaseOffset) Next() uint64 {
	return ExtractBits(uint64(d), 51, 12) // 4-byte stride
}
func (d DyldChainedPtr64RebaseOffset) Bind() uint64 {
	return ExtractBits(uint64(d), 63, 1) // == 0
}
func (d DyldChainedPtr64RebaseOffset) String() string {
	return fmt.Sprintf("offset: 0x%016x, next: %d", d.Offset(), d.Next())
}

// DYLD_CHAINED_PTR_ARM64E_USERLAND24
type DyldChainedPtrArm64eBind24 uint64

func (d DyldChainedPtrArm64eBind24) Ordinal() uint {
	return uint(ExtractBits(uint64(d), 0, 24))
}
func (d DyldChainedPtrArm64eBind24) Zero() uint64 {
	return ExtractBits(uint64(d), 24, 8)
}
func (d DyldChainedPtrArm64eBind24) Addend() uint64 {
	return ExtractBits(uint64(d), 32, 19)
}
func (d DyldChainedPtrArm64eBind24) SignExtendedAddend() uint64 {
	addend19 := ExtractBits(uint64(d), 32, 19) // +/-256K
	if (addend19 & 0x40000) != 0 {
		return addend19 | 0xFFFFFFFFFFFC0000
	}
	return addend19
}
func (d DyldChainedPtrArm64eBind24) Next() uint64 {
	return ExtractBits(uint64(d), 51, 11)
}
func (d DyldChainedPtrArm64eBind24) Bind() uint64 {
	return ExtractBits(uint64(d), 62, 1)
}
func (d DyldChainedPtrArm64eBind24) Auth() uint64 {
	return ExtractBits(uint64(d), 63, 1)
}
func (d DyldChainedPtrArm64eBind24) String() string {
	return fmt.Sprintf("ordinal: %d, addend: %x, next: %d, is_bind: %t", d.Ordinal(), d.Addend(), d.Next(), d.Bind() == 1)
}

// DYLD_CHAINED_PTR_ARM64E_USERLAND24
type DyldChainedPtrArm64eAuthBind24 uint64

func (d DyldChainedPtrArm64eAuthBind24) Ordinal() uint {
	return uint(ExtractBits(uint64(d), 0, 24))
}
func (d DyldChainedPtrArm64eAuthBind24) Zero() uint64 {
	return ExtractBits(uint64(d), 24, 8)
}
func (d DyldChainedPtrArm64eAuthBind24) Diversity() uint64 {
	return ExtractBits(uint64(d), 32, 16)
}
func (d DyldChainedPtrArm64eAuthBind24) AddrDiv() uint64 {
	return ExtractBits(uint64(d), 48, 1)
}
func (d DyldChainedPtrArm64eAuthBind24) Key() uint64 {
	return ExtractBits(uint64(d), 49, 2)
}
func (d DyldChainedPtrArm64eAuthBind24) Next() uint64 {
	return ExtractBits(uint64(d), 51, 11)
}
func (d DyldChainedPtrArm64eAuthBind24) Bind() uint64 {
	return ExtractBits(uint64(d), 62, 1)
}
func (d DyldChainedPtrArm64eAuthBind24) Auth() uint64 {
	return ExtractBits(uint64(d), 63, 1)
}
func (d DyldChainedPtrArm64eAuthBind24) String() string {
	return fmt.Sprintf("ordinal: %d, diversity: %x, has_diversity: %t, key: %s, next: %d, is_bind: %t, is_auth: %t",
		d.Ordinal(),
		d.Diversity(),
		d.AddrDiv() == 1,
		KeyName(d.Key()),
		d.Next(),
		d.Bind() == 1,
		d.Auth() == 1)
}

// DYLD_CHAINED_PTR_64
type DyldChainedPtr64Bind uint64

func (d DyldChainedPtr64Bind) Ordinal() uint {
	return uint(ExtractBits(uint64(d), 0, 24))
}
func (d DyldChainedPtr64Bind) Addend() uint64 {
	return ExtractBits(uint64(d), 24, 8) // 0 thru 255
}
func (d DyldChainedPtr64Bind) Reserved() uint64 {
	return ExtractBits(uint64(d), 32, 19) // all zeros
}
func (d DyldChainedPtr64Bind) Next() uint64 {
	return ExtractBits(uint64(d), 51, 12) // 4-byte stride
}
func (d DyldChainedPtr64Bind) Bind() uint64 {
	return ExtractBits(uint64(d), 63, 1) // == 1
}
func (d DyldChainedPtr64Bind) String() string {
	return fmt.Sprintf("ordinal: %d, addend: %d, next: %d, is_bind: %t",
		d.Ordinal(),
		d.Addend(),
		d.Next(),
		d.Bind() == 1)
}

// DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE
type DyldChainedPtr64KernelCacheRebase uint64

func (d DyldChainedPtr64KernelCacheRebase) Offset() uint {
	return uint(ExtractBits(uint64(d), 0, 30)) // basePointers[cacheLevel] + target
}
func (d DyldChainedPtr64KernelCacheRebase) CacheLevel() uint64 {
	return ExtractBits(uint64(d), 30, 2) // what level of cache to bind to (indexes a mach_header array)
}
func (d DyldChainedPtr64KernelCacheRebase) Diversity() uint64 {
	return ExtractBits(uint64(d), 32, 16)
}
func (d DyldChainedPtr64KernelCacheRebase) AddrDiv() uint64 {
	return ExtractBits(uint64(d), 48, 1)
}
func (d DyldChainedPtr64KernelCacheRebase) Key() uint64 {
	return ExtractBits(uint64(d), 49, 2)
}
func (d DyldChainedPtr64KernelCacheRebase) Next() uint64 {
	return ExtractBits(uint64(d), 51, 12) // 1 or 4-byte stide
}
func (d DyldChainedPtr64KernelCacheRebase) IsAuth() uint64 {
	return ExtractBits(uint64(d), 63, 1)
}
func (d DyldChainedPtr64KernelCacheRebase) String() string {
	return fmt.Sprintf("offset: 0x%08x, cacheLevel: %d, diversity: %x, has_diversity: %t, key: %s, next: %d, is_auth: %t",
		d.Offset(),
		d.CacheLevel(),
		d.Diversity(),
		d.AddrDiv() == 1,
		KeyName(d.Key()),
		d.Next(),
		d.IsAuth() == 1)
}

// DYLD_CHAINED_PTR_32
// Note: for DYLD_CHAINED_PTR_32 some non-pointer values are co-opted into the chain
// as out of range rebases.  If an entry in the chain is > max_valid_pointer, then it
// is not a pointer.  To restore the value, subtract off the bias, which is
// (64MB+max_valid_pointer)/2.
type DyldChainedPtr32Rebase uint32

func (d DyldChainedPtr32Rebase) Offset() uint {
	return uint(ExtractBits(uint64(d), 0, 26)) // vmaddr, 64MB max image size
}
func (d DyldChainedPtr32Rebase) Next() uint32 {
	return uint32(ExtractBits(uint64(d), 26, 5)) // 4-byte stride
}
func (d DyldChainedPtr32Rebase) Bind() uint32 {
	return uint32(ExtractBits(uint64(d), 31, 1)) // == 0
}
func (d DyldChainedPtr32Rebase) String() string {
	return fmt.Sprintf("vmaddr: 0x%08x, next: %d", d.Offset(), d.Next())
}

// DYLD_CHAINED_PTR_32
type DyldChainedPtr32Bind uint32

func (d DyldChainedPtr32Bind) Ordinal() uint {
	return uint(ExtractBits(uint64(d), 0, 20))
}
func (d DyldChainedPtr32Bind) Addend() uint32 {
	return uint32(ExtractBits(uint64(d), 20, 6)) // 0 thru 63
}
func (d DyldChainedPtr32Bind) Next() uint32 {
	return uint32(ExtractBits(uint64(d), 26, 5)) // 4-byte stride
}
func (d DyldChainedPtr32Bind) Bind() uint32 {
	return uint32(ExtractBits(uint64(d), 31, 1)) // == 1
}
func (d DyldChainedPtr32Bind) String() string {
	return fmt.Sprintf("ordinal: %d, addend: %x, next: %d, is_bind: %t", d.Ordinal(), d.Addend(), d.Next(), d.Bind() == 1)
}

// DYLD_CHAINED_PTR_32_CACHE
type DyldChainedPtr32CacheRebase uint32

func (d DyldChainedPtr32CacheRebase) Offset() uint {
	return uint(ExtractBits(uint64(d), 0, 30)) // 1GB max dyld cache TEXT and DATA
}
func (d DyldChainedPtr32CacheRebase) Next() uint32 {
	return uint32(ExtractBits(uint64(d), 30, 2)) // 4-byte stride
}
func (d DyldChainedPtr32CacheRebase) String() string {
	return fmt.Sprintf("offset: 0x%08x, next: %d", d.Offset(), d.Next())
}

// DYLD_CHAINED_PTR_32_FIRMWARE
type DyldChainedPtr32FirmwareRebase uint32

func (d DyldChainedPtr32FirmwareRebase) Offset() uint {
	return uint(ExtractBits(uint64(d), 0, 26)) // 64MB max firmware TEXT and DATA
}
func (d DyldChainedPtr32FirmwareRebase) Next() uint32 {
	return uint32(ExtractBits(uint64(d), 26, 6)) // 4-byte stride
}
func (d DyldChainedPtr32FirmwareRebase) String() string {
	return fmt.Sprintf("offset: 0x%08x, next: %d", d.Offset(), d.Next())
}

// DCImportsFormat are values for dyld_chained_fixups_header.imports_format
type DCImportsFormat uint32

const (
	DC_IMPORT          DCImportsFormat = 1
	DC_IMPORT_ADDEND   DCImportsFormat = 2
	DC_IMPORT_ADDEND64 DCImportsFormat = 3
)

// DYLD_CHAINED_IMPORT
type DyldChainedImport uint32

func (d DyldChainedImport) LibOrdinal() uint8 {
	return uint8(ExtractBits(uint64(d), 0, 8))
}
func (d DyldChainedImport) WeakImport() bool {
	return ExtractBits(uint64(d), 8, 1) == 1
}
func (d DyldChainedImport) NameOffset() uint32 {
	return uint32(ExtractBits(uint64(d), 9, 23))
}

func (i DyldChainedImport) String() string {
	return fmt.Sprintf("lib ordinal: %d, is_weak: %t", i.LibOrdinal(), i.WeakImport())
}

type DyldChainedImport64 uint64

func (d DyldChainedImport64) LibOrdinal() uint64 {
	return ExtractBits(uint64(d), 0, 16)
}
func (d DyldChainedImport64) WeakImport() bool {
	return ExtractBits(uint64(d), 16, 1) == 1
}
func (d DyldChainedImport64) Reserved() uint64 {
	return ExtractBits(uint64(d), 17, 15)
}
func (d DyldChainedImport64) NameOffset() uint64 {
	return ExtractBits(uint64(d), 32, 32)
}

func (i DyldChainedImport64) String() string {
	return fmt.Sprintf("lib ordinal: %d, is_weak: %t", i.LibOrdinal(), i.WeakImport())
}

// DYLD_CHAINED_IMPORT_ADDEND
type DyldChainedImportAddend struct {
	Import DyldChainedImport
	Addend int32
}

func (i DyldChainedImportAddend) String() string {
	return fmt.Sprintf("lib ordinal: %d, is_weak: %t, addend: 0x%08x", i.Import.LibOrdinal(), i.Import.WeakImport(), i.Addend)
}

// DYLD_CHAINED_IMPORT_ADDEND64
type DyldChainedImportAddend64 struct {
	Import DyldChainedImport64
	Addend uint64
}

func (i DyldChainedImportAddend64) String() string {
	return fmt.Sprintf("lib ordinal: %d, is_weak: %t, addend: 0x%016x", i.Import.LibOrdinal(), i.Import.WeakImport(), i.Addend)
}
