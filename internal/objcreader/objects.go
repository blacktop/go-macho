package objcreader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

// GetCFStrings returns the Objective-C CFStrings
func (f *Reader) GetCFStrings() ([]objc.CFString, error) {
	var err error
	var cfstrings []objc.CFString

	// Cache only for this call. A failed section read also gets cached so that
	// subsequent entries use the existing address reader without retrying it.
	texts := make(map[*types.Section]string)
	readCString := func(addr uint64) (string, error) {
		for _, sec := range f.Sections() {
			if !sec.Flags.IsCstringLiterals() || addr < sec.Addr || addr-sec.Addr >= sec.Size {
				continue
			}
			text, ok := texts[sec]
			if !ok {
				dat := make([]byte, sec.Size)
				if n, err := f.DataReader().ReadAtAddr(dat, sec.Addr); err == nil && n == len(dat) {
					text = string(dat)
				}
				texts[sec] = text
			}
			off := addr - sec.Addr
			if off < uint64(len(text)) {
				tail := text[off:]
				// Match GetCString's 1 MiB limit; preserve its errors and
				// cross-section reads by falling back when no NUL is found.
				if len(tail) > 1<<20 {
					tail = tail[:1<<20]
				}
				if end := strings.IndexByte(tail, 0); end >= 0 {
					return tail[:end], nil
				}
			}
			break
		}
		return f.GetCString(addr)
	}

	for _, s := range f.SegmentNames() {
		if sec := f.Section(s, "__cfstring"); sec != nil {
			if err := f.DataReader().SeekToAddr(sec.Addr); err != nil {
				return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
			}

			dat := make([]byte, sec.Size)
			if err := binary.Read(f.DataReader(), f.ByteOrder(), dat); err != nil {
				return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
			}

			const recordSize = 32 // Four uint64 fields in CFString64Type.
			first := len(cfstrings)
			cfstrings = append(cfstrings, make([]objc.CFString, len(dat)/recordSize)...)
			for idx := first; idx < len(cfstrings); idx++ {
				local := idx - first
				record := dat[local*recordSize : (local+1)*recordSize]
				cfstrings[idx].CFString64Type = objc.CFString64Type{
					IsaVMAddr: f.ByteOrder().Uint64(record[0:8]),
					Info:      f.ByteOrder().Uint64(record[8:16]),
					Data:      f.ByteOrder().Uint64(record[16:24]),
					Length:    f.ByteOrder().Uint64(record[24:32]),
				}
			}

			for idx := first; idx < len(cfstrings); idx++ {
				cfstrings[idx].IsaVMAddr = f.ConvertPointer(cfstrings[idx].IsaVMAddr)
				if bind, err := f.GetBindName(cfstrings[idx].IsaVMAddr); err == nil {
					cfstrings[idx].ISA = bind
				}
				cfstrings[idx].Data = f.ConvertPointer(cfstrings[idx].Data)
				if cfstrings[idx].Data == 0 {
					return nil, fmt.Errorf("unhandled cstring parse case where data is 0") // TODO: finish this
				}
				// Check encoding from Info field and use appropriate string reader
				if cfstrings[idx].IsUTF16() {
					cfstrings[idx].Name, err = f.GetUTF16String(cfstrings[idx].Data, cfstrings[idx].Length)
				} else {
					cfstrings[idx].Name, err = readCString(cfstrings[idx].Data)
				}
				if err != nil {
					return nil, fmt.Errorf("failed to read cfstring: %v", err)
				}
				if c, ok := f.GetObjC(cfstrings[idx].IsaVMAddr); ok {
					cfstrings[idx].Class = c.(*objc.Class)
				}
				cfstrings[idx].Address = sec.Addr + uint64((idx-first)*recordSize)
			}
		}
	}

	return cfstrings, nil
}

// GetObjCIntObj parses the __objc_intobj section and returns a map of
func (f *Reader) GetObjCIntegerObjects() (map[uint64]*objc.IntObj, error) {
	if sec := f.Section("__TEXT", "__objc_intobj"); sec != nil {
		if err := f.DataReader().SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}
		dat := make([]byte, sec.Size)
		if err := binary.Read(f.DataReader(), f.ByteOrder(), dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		intObjs := make([]objc.IntObj, int(sec.Size)/binary.Size(objc.IntObj{}))
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder(), &intObjs); err != nil {
			return nil, fmt.Errorf("failed to read %T structs: %v", intObjs, err)
		}

		intObjMap := make(map[uint64]*objc.IntObj)
		for idx := range intObjs {
			intObjMap[sec.Addr+uint64(idx*binary.Size(objc.IntObj{}))] = &intObjs[idx]
		}

		return intObjMap, nil
	}

	return nil, fmt.Errorf("macho does not contain __objc_intobj section: %w", ErrObjcSectionNotFound)
}

// GetObjCStubs returns the Objective-C stubs
func (f *Reader) GetObjCStubs(
	parse func(uint64, []byte) (map[uint64]*objc.Stub, error),
) (map[uint64]*objc.Stub, error) {
	if sec := f.Section("__TEXT", "__objc_stubs"); sec != nil {
		if err := f.DataReader().SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}
		dat := make([]byte, sec.Size)
		if err := binary.Read(f.DataReader(), f.ByteOrder(), dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}
		return parse(sec.Addr, dat)
	}

	return nil, fmt.Errorf("macho does not contain __objc_stubs section: %w", ErrObjcSectionNotFound)
}
