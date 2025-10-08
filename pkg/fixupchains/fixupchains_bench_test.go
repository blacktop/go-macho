package fixupchains_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/blacktop/go-macho"
	fixupchains "github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

type mockMachoReader struct {
	*bytes.Reader
}

func newMockMachoReader(data []byte) *mockMachoReader {
	return &mockMachoReader{bytes.NewReader(data)}
}

func (m *mockMachoReader) SeekToAddr(addr uint64) error {
	_, err := m.Seek(int64(addr), io.SeekStart)
	return err
}

func (m *mockMachoReader) ReadAtAddr(buf []byte, addr uint64) (int, error) {
	return m.ReadAt(buf, int64(addr))
}

func BenchmarkParseChainedFixups(b *testing.B) {
	cases := []struct {
		name   string
		fixups int
		binds  int
	}{
		{name: "rebases-128", fixups: 128, binds: 0},
		{name: "rebases-1024", fixups: 1024, binds: 0},
		{name: "mixed-512", fixups: 512, binds: 64},
		{name: "mixed-4096", fixups: 4096, binds: 512},
	}

	for _, tc := range cases {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			b.Helper()
			lcPayload, fileData, err := buildSyntheticChainPayload(fixupchains.DYLD_CHAINED_PTR_32, 0x4000, 1, tc.fixups, tc.binds)
			if err != nil {
				b.Fatalf("build payload: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reader := bytes.NewReader(lcPayload)
				mr := newMockMachoReader(fileData)
				sr := types.MachoReader(mr)
				dcf := fixupchains.NewChainedFixups(reader, &sr, binary.LittleEndian)
				if _, err := dcf.Parse(); err != nil {
					b.Fatalf("parse: %v", err)
				}
			}
		})
	}
}

func buildSyntheticChainPayload(ptrFormat fixupchains.DCPtrKind, pageSize uint16, pageCount uint16, fixupCount, bindCount int) ([]byte, []byte, error) {
	if fixupCount <= 0 {
		return nil, nil, fmt.Errorf("fixupCount must be positive")
	}
	if bindCount < 0 {
		return nil, nil, fmt.Errorf("bindCount must be non-negative")
	}
	if bindCount > fixupCount {
		bindCount = fixupCount
	}
	strideBytes := ptrStride(ptrFormat)
	capacity := int(pageSize) * int(pageCount)
	if fixupCount*strideBytes > capacity {
		return nil, nil, fmt.Errorf("requested %d fixups exceeds page capacity (%d bytes)", fixupCount, capacity)
	}

	pageStarts := make([]fixupchains.DCPtrStart, pageCount)
	for i := range pageStarts {
		pageStarts[i] = 0
	}

	seg := fixupchains.DyldChainedStartsInSegment{
		Size:            uint32(binary.Size(fixupchains.DyldChainedStartsInSegment{})) + uint32(len(pageStarts))*2,
		PageSize:        pageSize,
		PointerFormat:   ptrFormat,
		SegmentOffset:   0,
		MaxValidPointer: 0x03ffffff,
		PageCount:       pageCount,
	}

	var segBuf bytes.Buffer
	if err := binary.Write(&segBuf, binary.LittleEndian, seg); err != nil {
		return nil, nil, err
	}
	if err := binary.Write(&segBuf, binary.LittleEndian, pageStarts); err != nil {
		return nil, nil, err
	}

	var startsBuf bytes.Buffer
	segCount := uint32(1)
	if err := binary.Write(&startsBuf, binary.LittleEndian, segCount); err != nil {
		return nil, nil, err
	}
	segInfoOffsets := []uint32{uint32(4 + 4*segCount)}
	if err := binary.Write(&startsBuf, binary.LittleEndian, segInfoOffsets); err != nil {
		return nil, nil, err
	}
	if _, err := startsBuf.Write(segBuf.Bytes()); err != nil {
		return nil, nil, err
	}

	imports := make([]fixupchains.DyldChainedImport, bindCount)
	symbols := make([]byte, 0, bindCount*8)
	var symOffset uint32
	for i := 0; i < bindCount; i++ {
		name := fmt.Sprintf("_sym%d", i)
		imports[i] = fixupchains.DyldChainedImport(symOffset << 9)
		symbols = append(symbols, name...)
		symbols = append(symbols, 0)
		symOffset += uint32(len(name) + 1)
	}

	header := fixupchains.DyldChainedFixupsHeader{
		FixupsVersion: 0,
		StartsOffset:  uint32(binary.Size(fixupchains.DyldChainedFixupsHeader{})),
		ImportsOffset: 0,
		SymbolsOffset: 0,
		ImportsCount:  uint32(len(imports)),
		ImportsFormat: fixupchains.DC_IMPORT,
		SymbolsFormat: fixupchains.DC_SFORMAT_UNCOMPRESSED,
	}

	startsBytes := startsBuf.Bytes()
	header.ImportsOffset = header.StartsOffset + uint32(len(startsBytes))
	importsSize := uint32(len(imports)) * 4
	header.SymbolsOffset = header.ImportsOffset + importsSize
	if len(imports) == 0 {
		header.SymbolsOffset = header.ImportsOffset
	}

	var lcBuf bytes.Buffer
	if err := binary.Write(&lcBuf, binary.LittleEndian, header); err != nil {
		return nil, nil, err
	}
	if _, err := lcBuf.Write(startsBytes); err != nil {
		return nil, nil, err
	}
	if len(imports) > 0 {
		if err := binary.Write(&lcBuf, binary.LittleEndian, imports); err != nil {
			return nil, nil, err
		}
		if _, err := lcBuf.Write(symbols); err != nil {
			return nil, nil, err
		}
	}

	fileData := make([]byte, capacity)
	bindIndex := 0
	for i := 0; i < fixupCount; i++ {
		next := uint32(0)
		if i < fixupCount-1 {
			next = 1
		}
		offset := i * strideBytes
		switch {
		case bindIndex < bindCount:
			ordinal := uint32(bindIndex)
			addend := uint32(i & 0x3f)
			ptr := (uint32(1) << 31) | (next << 26) | (addend << 20) | ordinal
			binary.LittleEndian.PutUint32(fileData[offset:], ptr)
			bindIndex++
		default:
			target := uint32(0x200000 + i*0x10)
			ptr := target | (next << 26)
			binary.LittleEndian.PutUint32(fileData[offset:], ptr)
		}
	}

	return lcBuf.Bytes(), fileData, nil
}

func ptrStride(kind fixupchains.DCPtrKind) int {
	switch kind {
	case fixupchains.DYLD_CHAINED_PTR_ARM64E,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND24,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
		return 8
	case fixupchains.DYLD_CHAINED_PTR_ARM64E_KERNEL,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_FIRMWARE,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_SEGMENTED,
		fixupchains.DYLD_CHAINED_PTR_32_FIRMWARE,
		fixupchains.DYLD_CHAINED_PTR_64,
		fixupchains.DYLD_CHAINED_PTR_64_OFFSET,
		fixupchains.DYLD_CHAINED_PTR_32,
		fixupchains.DYLD_CHAINED_PTR_32_CACHE,
		fixupchains.DYLD_CHAINED_PTR_64_KERNEL_CACHE:
		return 4
	case fixupchains.DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		return 1
	default:
		panic(fmt.Sprintf("unsupported pointer format: %d", kind))
	}
}

func BenchmarkParseChainedFixupsLSArm64e(b *testing.B) {
	benchmarkParseChainedFixupsFromFile(b, "/tmp/ls.arm64e")
}

func BenchmarkParseChainedFixupsKernelCache(b *testing.B) {
	benchmarkParseChainedFixupsFromFile(b, "/Users/blacktop/Developer/Mine/blacktop/ipsw/test-caches/IPSWs/IOS/23A340__iPhone17,1/kernelcache.release.iPhone17,1")
}

func benchmarkParseChainedFixupsFromFile(b *testing.B, binPath string) {
	b.Helper()
	info, err := os.Stat(binPath)
	if err != nil {
		if os.IsNotExist(err) {
			b.Skipf("test binary %s not found", binPath)
			return
		}
		b.Fatalf("stat %s: %v", binPath, err)
	}

	b.StopTimer()
	raw, err := os.ReadFile(binPath)
	if err != nil {
		b.Fatalf("read %s: %v", binPath, err)
	}

	mf, err := macho.NewFile(bytes.NewReader(raw))
	if err != nil {
		b.Fatalf("parse Mach-O %s: %v", binPath, err)
	}

	var lc *macho.DyldChainedFixups
	for _, load := range mf.Loads {
		if candidate, ok := load.(*macho.DyldChainedFixups); ok {
			lc = candidate
			break
		}
	}
	if lc == nil || lc.Size == 0 {
		b.Skipf("%s lacks LC_DYLD_CHAINED_FIXUPS", binPath)
		return
	}

	start := int(lc.Offset)
	end := start + int(lc.Size)
	if start < 0 || end > len(raw) || start >= end {
		b.Fatalf("invalid fixups range [%d:%d] for %s", start, end, binPath)
	}

	lcPayload := make([]byte, lc.Size)
	copy(lcPayload, raw[start:end])
	segments := mf.Segments()
	order := mf.ByteOrder

	b.ReportMetric(float64(info.Size())/1e6, "binary_MB")
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(lcPayload)
		mr := newMockMachoReader(raw)
		sr := types.MachoReader(mr)
		dcf := fixupchains.NewChainedFixups(reader, &sr, order)
		if err := dcf.ParseStarts(); err != nil {
			b.Fatalf("parse starts: %v", err)
		}
		for idx := range dcf.Starts {
			if idx < len(segments) && dcf.Starts[idx].PageStarts != nil {
				dcf.Starts[idx].SegmentOffset = segments[idx].Offset
			}
		}
		if _, err := dcf.Parse(); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}
