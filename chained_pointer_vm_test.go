package macho_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

const chainedVMBase = uint64(0x100000000)

// chainedPointerImage has no __PAGEZERO and contains three real chains. The second and third
// use runtime offsets that are numerically also VM addresses in __DATA, but target __FAR.
func chainedPointerImage(t *testing.T, format fixupchains.DCPtrKind) []byte {
	t.Helper()
	write := func(buf *bytes.Buffer, value any) {
		t.Helper()
		if err := binary.Write(buf, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}

	const segmentCount = 4
	const linkeditOffset = 0x5000
	var starts bytes.Buffer
	write(&starts, uint32(segmentCount))
	write(&starts, [segmentCount]uint32{0, 4 + 4*segmentCount, 0, 0})
	write(&starts, fixupchains.DyldChainedStartsInSegment{
		Size:          uint32(binary.Size(fixupchains.DyldChainedStartsInSegment{}) + 3*2),
		PageSize:      0x1000,
		PointerFormat: format,
		SegmentOffset: 0x1000,
		PageCount:     3,
	})
	write(&starts, [3]uint16{0x100, 0x100, 0x100})
	end := uint32(binary.Size(fixupchains.DyldChainedFixupsHeader{}) + starts.Len())
	var fixups bytes.Buffer
	write(&fixups, fixupchains.DyldChainedFixupsHeader{
		StartsOffset:  uint32(binary.Size(fixupchains.DyldChainedFixupsHeader{})),
		ImportsOffset: end,
		SymbolsOffset: end,
		ImportsFormat: fixupchains.DC_IMPORT,
	})
	fixups.Write(starts.Bytes())

	var image bytes.Buffer
	commandSize := segmentCount*binary.Size(types.Segment64{}) +
		binary.Size(types.LinkEditDataCmd{})
	write(&image, types.FileHeader{
		Magic:        types.Magic64,
		CPU:          types.CPUArm64,
		Type:         types.MH_EXECUTE,
		NCommands:    segmentCount + 1,
		SizeCommands: uint32(commandSize),
	})
	segment := func(name string, addr, memsz, offset, filesz uint64) {
		t.Helper()
		seg := types.Segment64{
			LoadCmd: types.LC_SEGMENT_64,
			Len:     uint32(binary.Size(types.Segment64{})),
			Addr:    addr,
			Memsz:   memsz,
			Offset:  offset,
			Filesz:  filesz,
		}
		copy(seg.Name[:], name)
		write(&image, seg)
	}
	segment("__TEXT", chainedVMBase, 0x1000, 0, 0x1000)
	segment("__DATA", chainedVMBase+0x1000, 0x5000, 0x1000, 0x4000)
	fixupSize := uint64(fixups.Len())
	segment("__LINKEDIT", chainedVMBase+0x6000, fixupSize, linkeditOffset, fixupSize)
	segment("__FAR", 2*chainedVMBase+0x1000, 0x5000, linkeditOffset, 0)
	write(&image, types.LinkEditDataCmd{
		LoadCmd: types.LC_DYLD_CHAINED_FIXUPS,
		Len:     uint32(binary.Size(types.LinkEditDataCmd{})),
		Offset:  linkeditOffset,
		Size:    uint32(fixups.Len()),
	})

	data := make([]byte, linkeditOffset+fixups.Len())
	copy(data, image.Bytes())
	copy(data[linkeditOffset:], fixups.Bytes())
	stride, ok := fixupchains.Stride(format)
	if !ok {
		t.Fatalf("unsupported test pointer format %d", format)
	}
	binary.LittleEndian.PutUint64(data[0x1100:], 0x1200|(8/stride)<<51)
	binary.LittleEndian.PutUint64(data[0x1108:], 0x1200)
	binary.LittleEndian.PutUint64(data[0x2100:], chainedVMBase+0x1200)
	binary.LittleEndian.PutUint64(data[0x3100:], chainedVMBase+0x5200)
	return data
}

func TestChainedPointerVMConversion(t *testing.T) {
	for _, format := range []fixupchains.DCPtrKind{
		fixupchains.DYLD_CHAINED_PTR_64_OFFSET,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND24,
	} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			data := chainedPointerImage(t, format)
			f, err := macho.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			dcf, err := f.DyldChainedFixups()
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name   string
				offset uint64
				want   uint64
			}{
				{"encoded next", 0x1100, chainedVMBase + 0x1200},
				{"zero next", 0x1108, chainedVMBase + 0x1200},
				{"offset overlaps file-backed VA", 0x2100, 2*chainedVMBase + 0x1200},
				{"offset overlaps zero-fill VA", 0x3100, 2*chainedVMBase + 0x5200},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := dcf.GetFixupAtOffset(tc.offset); err != nil {
						t.Fatalf("fixture offset %#x is not in a chain: %v", tc.offset, err)
					}
					if got, err := f.GetPointer(tc.offset); err != nil || got != tc.want {
						t.Errorf("GetPointer() = %#x, %v; want %#x", got, err, tc.want)
					}
					if got, err := f.GetPointerAtAddress(chainedVMBase + tc.offset); err != nil || got != tc.want {
						t.Errorf("GetPointerAtAddress() = %#x, %v; want %#x", got, err, tc.want)
					}
					raw := binary.LittleEndian.Uint64(data[tc.offset:])
					if got := f.SlidePointer(raw); got != tc.want {
						t.Errorf("SlidePointer(%#x) = %#x; want %#x", raw, got, tc.want)
					}
					got, err := f.GetSlidPointerAtAddress(chainedVMBase + tc.offset)
					if err != nil || got != tc.want {
						t.Errorf("GetSlidPointerAtAddress() = %#x, %v; want %#x", got, err, tc.want)
					}
				})
			}
		})
	}
}

func TestChainedPointerConfiguredConverter(t *testing.T) {
	const external = uint64(0x700001108)
	for _, format := range []fixupchains.DCPtrKind{
		fixupchains.DYLD_CHAINED_PTR_64_OFFSET,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND24,
	} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			data := chainedPointerImage(t, format)
			binary.LittleEndian.PutUint32(data[24:], uint32(types.DylibInCache))
			vma := types.VMAddrConverter{
				Converter: func(value uint64) uint64 { return value + external },
				VMAddr2Offet: func(addr uint64) (uint64, error) {
					if addr == external {
						return 0x1108, nil
					}
					return 0, fmt.Errorf("unexpected address %#x", addr)
				},
			}
			reader := types.NewCustomSectionReader(bytes.NewReader(data), &vma, 0, int64(len(data)))
			config := macho.FileConfig{CacheReader: reader, VMAddrConverter: vma}
			f, err := macho.NewFile(bytes.NewReader(data), config)
			if err != nil {
				t.Fatal(err)
			}
			if got := f.SlidePointer(0x1200); got != external+0x1200 {
				t.Fatalf("SlidePointer() = %#x", got)
			}
			for _, read := range []func(uint64) (uint64, error){
				f.GetPointerAtAddress, f.GetSlidPointerAtAddress,
			} {
				if got, err := read(external); err != nil || got != external+0x1200 {
					t.Fatalf("configured pointer = %#x, %v", got, err)
				}
			}
		})
	}
}

func TestChainedPointerRebasedContent(t *testing.T) {
	const target = chainedVMBase + 0x1200
	for _, format := range []fixupchains.DCPtrKind{
		fixupchains.DYLD_CHAINED_PTR_64_OFFSET,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND24,
	} {
		for _, slide := range []int64{0x2000, -0x1000} {
			data := chainedPointerImage(t, format)
			raw := target + uint64(slide)
			binary.LittleEndian.PutUint64(data[0x1108:], raw)
			config := macho.FileConfig{VMAddrConverter: types.VMAddrConverter{
				IsContentRebased: true, Slide: slide,
			}}
			f, err := macho.NewFile(bytes.NewReader(data), config)
			if err != nil {
				t.Fatal(err)
			}
			if got := f.SlidePointer(raw); got != target || f.SlidePointer(0) != 0 {
				t.Fatalf("format=%d slide=%#x converted=%#x", format, slide, got)
			}
			for _, read := range []func(uint64) (uint64, error){
				f.GetPointerAtAddress, f.GetSlidPointerAtAddress,
			} {
				if got, err := read(chainedVMBase + 0x1108); err != nil || got != target {
					t.Fatalf("format=%d slide=%#x pointer=%#x error=%v", format, slide, got, err)
				}
			}
		}
	}
}

func TestConfiguredPointerWidth(t *testing.T) {
	var commands bytes.Buffer
	segment := types.Segment32{
		LoadCmd: types.LC_SEGMENT, Len: uint32(binary.Size(types.Segment32{})),
		Addr: 0x1000, Memsz: 0x100, Filesz: 0x100,
	}
	if err := binary.Write(&commands, binary.LittleEndian, segment); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 0x100)
	header := types.FileHeader{
		Magic: types.Magic32, CPU: types.CPUArm, Type: types.MH_EXECUTE,
		NCommands: 1, SizeCommands: uint32(commands.Len()),
	}
	copy(data[header.Put(data, binary.LittleEndian):], commands.Bytes())
	binary.LittleEndian.PutUint32(data[0xfc:], 0x1234)
	config := macho.FileConfig{VMAddrConverter: types.VMAddrConverter{
		Converter: func(value uint64) uint64 { return value + 0x1000 },
	}}
	f, err := macho.NewFile(bytes.NewReader(data), config)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.GetSlidPointerAtAddress(0x10fc); err != nil || got != 0x2234 {
		t.Fatalf("32-bit pointer = %#x, %v", got, err)
	}
}
