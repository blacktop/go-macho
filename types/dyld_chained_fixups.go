package types

type DCSymbolsFormat uint32

const (
	DC_SFORMAT_UNCOMPRESSED    DCSymbolsFormat = 0
	DC_SFORMAT_ZLIB_COMPRESSED DCSymbolsFormat = 1
)

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
}

type DCPtrStart uint16

const (
	DYLD_CHAINED_PTR_START_NONE  DCPtrStart = 0xFFFF // used in page_start[] to denote a page with no fixups
	DYLD_CHAINED_PTR_START_MULTI DCPtrStart = 0x8000 // used in page_start[] to denote a page which has multiple starts
	DYLD_CHAINED_PTR_START_LAST  DCPtrStart = 0x8000 // used in chain_starts[] to denote last start in list for page
)

// DYLD_CHAINED_PTR_ARM64E
type DyldChainedPtrArm64eRebase uint64

func (d DyldChainedPtrArm64eRebase) Target() uint64 {
	return ExtractBits(uint64(d), 0, 43)
}
func (d DyldChainedPtrArm64eRebase) High8() uint64 {
	return ExtractBits(uint64(d), 43, 8)
}
func (d DyldChainedPtrArm64eRebase) Next() uint64 {
	return ExtractBits(uint64(d), 51, 11)
}
func (d DyldChainedPtrArm64eRebase) Bind() uint64 {
	return ExtractBits(uint64(d), 62, 1)
}
func (d DyldChainedPtrArm64eRebase) Auth() uint64 {
	return ExtractBits(uint64(d), 63, 1)
}

// DYLD_CHAINED_PTR_ARM64E
type DyldChainedPtrArm64eBind uint64

// DYLD_CHAINED_PTR_ARM64E
type DyldChainedPtrArm64eAuthRebase uint64

// DYLD_CHAINED_PTR_ARM64E
type DyldChainedPtrArm64eAuthBind uint64

// DYLD_CHAINED_PTR_64/DYLD_CHAINED_PTR_64_OFFSET
type DyldChainedPtr_64Rebase uint64

// DYLD_CHAINED_PTR_ARM64E_USERLAND24
type DyldChainedPtrArm64eBind24 uint64

// DYLD_CHAINED_PTR_ARM64E_USERLAND24
type DyldChainedPtrArm64eAuthBind24 uint64

// DYLD_CHAINED_PTR_64
type DyldChainedPtr_64Bind uint64

// DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE
type DyldChainedPtr_64KernelCacheRebase uint64

// DYLD_CHAINED_PTR_32
// Note: for DYLD_CHAINED_PTR_32 some non-pointer values are co-opted into the chain
// as out of range rebases.  If an entry in the chain is > max_valid_pointer, then it
// is not a pointer.  To restore the value, subtract off the bias, which is
// (64MB+max_valid_pointer)/2.
type DyldChainedPtr_32Rebase uint32

// DYLD_CHAINED_PTR_32
type DyldChainedPtr_32Bind uint32

// DYLD_CHAINED_PTR_32_CACHE
type DyldChainedPtr_32CacheRebase uint32

// DYLD_CHAINED_PTR_32_FIRMWARE
type DyldChainedPtr_32FirmwareRebase uint32

// DCImportsFormat are values for dyld_chained_fixups_header.imports_format
type DCImportsFormat uint32

const (
	DC_IMPORT          DCImportsFormat = 1
	DC_IMPORT_ADDEND   DCImportsFormat = 2
	DC_IMPORT_ADDEND64 DCImportsFormat = 3
)

// DYLD_CHAINED_IMPORT
type DyldChainedImport uint32

// DYLD_CHAINED_IMPORT_ADDEND
type DyldChainedImportAddend struct {
	Import uint32
	Addend int32
}

// DYLD_CHAINED_IMPORT_ADDEND64
type DyldChainedImportAddend64 struct {
	Import uint64
	Addend uint64
}
