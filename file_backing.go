package macho

import (
	"fmt"

	"github.com/blacktop/go-macho/types"
)

func (f *File) segmentForFileAddress(address uint64) *Segment {
	for _, load := range f.Loads {
		seg, ok := load.(*Segment)
		if ok && address >= seg.Addr && address-seg.Addr < seg.Memsz {
			return seg
		}
	}
	return nil
}

func (f *File) getOffset(address uint64) (uint64, error) {
	seg := f.segmentForFileAddress(address)
	if seg == nil {
		return 0, fmt.Errorf("address %#x not within any segment's adress range", address)
	}
	delta := address - seg.Addr
	if delta > ^uint64(0)-seg.Offset {
		return 0, fmt.Errorf("file offset for address %#x overflows", address)
	}
	return seg.Offset + delta, nil
}

// fileDataSize bounds an address range for the active reader. Standalone files
// are limited to contiguous file backing; caller-supplied address maps own backing.
// The underlying reader can still report a truncated file.
func (f *File) fileDataSize(addr, max uint64) uint64 {
	if max == 0 {
		return 0
	}
	if max-1 > ^uint64(0)-addr {
		max = ^uint64(0) - addr + 1
	}
	if f.customAddressReader {
		return max
	}
	return f.standaloneFileDataSize(addr, max)
}

func (f *File) standaloneFileDataSize(addr, max uint64) uint64 {
	seg := f.segmentForFileAddress(addr)
	if seg == nil {
		return 0
	}
	size := segmentFileDataSize(seg, addr, max)
	if size == 0 {
		return 0
	}
	// The live global slice preserves cross-segment overlaps and caller mutations.
	for _, sec := range f.Sections {
		if !zeroFillOverlaps(sec, addr, size) {
			continue
		}
		if addr >= sec.Addr {
			return 0
		}
		size = sec.Addr - addr
	}
	return size
}

// segmentFileDataSize requires a nonzero max and an address contained by seg.
func segmentFileDataSize(seg *Segment, addr, max uint64) uint64 {
	delta := addr - seg.Addr
	if delta >= seg.Filesz || delta > ^uint64(0)-seg.Offset {
		return 0
	}
	offset := seg.Offset + delta
	const readerLimit = uint64(1<<63 - 1)
	if offset >= readerLimit {
		return 0
	}
	size := max
	for _, limit := range []uint64{seg.Memsz - delta, seg.Filesz - delta, readerLimit - offset} {
		if limit < size {
			size = limit
		}
	}
	return size
}

func zeroFillOverlaps(sec *types.Section, addr, size uint64) bool {
	if sec.Size == 0 {
		return false
	}
	if sec.Addr <= addr {
		if addr-sec.Addr >= sec.Size {
			return false
		}
	} else if sec.Addr-addr >= size {
		return false
	}
	return sec.Flags.IsZerofill() || sec.Flags.IsGbZerofill() ||
		sec.Flags.IsThreadLocalZerofill()
}

func (f *File) hasFileData(addr, size uint64) bool {
	return size != 0 && f.fileDataSize(addr, size) == size
}

func (f *File) hasZeroFillData(addr, size uint64) bool {
	if size == 0 || size-1 > ^uint64(0)-addr {
		return false
	}
	seg := f.segmentForFileAddress(addr)
	if seg == nil {
		return false
	}
	delta := addr - seg.Addr
	if size > seg.Memsz-delta {
		return false
	}
	if delta >= seg.Filesz {
		return true
	}
	for _, sec := range f.Sections {
		if zeroFillContains(sec, addr, size) {
			return true
		}
	}
	return false
}

func zeroFillContains(sec *types.Section, addr, size uint64) bool {
	return zeroFillOverlaps(sec, addr, size) && addr >= sec.Addr &&
		size <= sec.Size-(addr-sec.Addr)
}

func (f *File) checkFileData(addr, size uint64) error {
	if size == 0 {
		return nil
	}
	if addr > ^uint64(0)-(size-1) {
		return fmt.Errorf("file data range at address %#x with size %#x overflows", addr, size)
	}
	if !f.hasFileData(addr, size) {
		return fmt.Errorf("no file data at address %#x with size %#x", addr, size)
	}
	return nil
}
