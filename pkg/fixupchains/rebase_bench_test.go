package fixupchains_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/blacktop/go-macho"
	fixupchains "github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

type rebaseOperation struct {
	offset uint64
	addr   uint64
	raw    uint64
}

func BenchmarkRebaseRawKernelcacheLarge(b *testing.B) {
	const kernelcachePath = "/Users/blacktop/Developer/Mine/blacktop/ipsw/test-caches/IPSWs/IOS/23A341__iPhone17,1/kernelcache.release.iPhone17,1"

	info, err := os.Stat(kernelcachePath)
	if err != nil {
		if os.IsNotExist(err) {
			b.Skipf("kernelcache %s not found", kernelcachePath)
			return
		}
		b.Fatalf("stat %s: %v", kernelcachePath, err)
	}

	raw, err := os.ReadFile(kernelcachePath)
	if err != nil {
		b.Fatalf("read %s: %v", kernelcachePath, err)
	}

	mf, err := macho.NewFile(bytes.NewReader(raw))
	if err != nil {
		b.Fatalf("parse Mach-O: %v", err)
	}

	var lc *macho.DyldChainedFixups
	for _, load := range mf.Loads {
		if candidate, ok := load.(*macho.DyldChainedFixups); ok {
			lc = candidate
			break
		}
	}
	if lc == nil || lc.Size == 0 {
		b.Skipf("%s lacks LC_DYLD_CHAINED_FIXUPS", kernelcachePath)
		return
	}

	start := int(lc.Offset)
	end := start + int(lc.Size)
	if start < 0 || end > len(raw) || start >= end {
		b.Fatalf("invalid fixups payload range [%d:%d]", start, end)
	}

	lcPayload := make([]byte, lc.Size)
	copy(lcPayload, raw[start:end])

	reader := bytes.NewReader(lcPayload)
	mr := newMockMachoReader(raw)
	sr := types.MachoReader(mr)
	dcf := fixupchains.NewChainedFixups(reader, &sr, mf.ByteOrder)

	if err := dcf.ParseStarts(); err != nil {
		b.Fatalf("parse starts: %v", err)
	}

	segments := mf.Segments()
	for idx, start := range dcf.Starts {
		if idx < len(segments) && start.PageStarts != nil {
			dcf.Starts[idx].SegmentOffset = segments[idx].Offset
		}
	}
	dcf.ResetSegmentIndex()

	const maxSamples = 4096
	baseAddr := mf.GetBaseAddress()
	ops := make([]rebaseOperation, 0, maxSamples)

	for segIdx := range dcf.Starts {
		start := &dcf.Starts[segIdx]
		if start.PageStarts == nil || start.PageCount == 0 {
			continue
		}
		ptrSize := fixupchains.PointerSize(start.PointerFormat)
		if ptrSize != 4 && ptrSize != 8 {
			continue
		}
		for pageIndex := uint16(0); pageIndex < start.PageCount; pageIndex++ {
			entry := start.PageStarts[pageIndex]
			if entry == fixupchains.DYLD_CHAINED_PTR_START_NONE {
				continue
			}
			if entry&fixupchains.DYLD_CHAINED_PTR_START_MULTI != 0 {
				continue
			}

			segment := segments[segIdx]
			fixupOffset := start.SegmentOffset + uint64(pageIndex)*uint64(start.PageSize) + uint64(entry)
			if fixupOffset+uint64(ptrSize) > uint64(len(raw)) {
				continue
			}
			idx := int(fixupOffset)
			bytesSlice := raw[idx : idx+ptrSize]
			var rawPtr uint64
			if ptrSize == 4 {
				rawPtr = uint64(mf.ByteOrder.Uint32(bytesSlice))
			} else {
				rawPtr = mf.ByteOrder.Uint64(bytesSlice)
			}
			if _, err := dcf.RebaseRaw(fixupOffset, rawPtr, baseAddr); err != nil {
				continue
			}
			addr := segment.Addr + (fixupOffset - segment.Offset)
			ops = append(ops, rebaseOperation{offset: fixupOffset, addr: addr, raw: rawPtr})
			if len(ops) >= maxSamples {
				break
			}
		}
		if len(ops) >= maxSamples {
			break
		}
	}

	if len(ops) == 0 {
		b.Skip("no rebase pointers collected for benchmark")
		return
	}

	b.ReportAllocs()
	b.ReportMetric(float64(info.Size())/1e6, "binary_MB")

	b.Run("RebaseRaw", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			op := ops[i%len(ops)]
			if _, err := dcf.RebaseRaw(op.offset, op.raw, baseAddr); err != nil {
				b.Fatalf("rebase raw: %v", err)
			}
		}
	})

	b.Run("GetSlidPointerAtAddress", func(b *testing.B) {
		mf.ResetFixupsCache()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			op := ops[i%len(ops)]
			if _, err := mf.GetSlidPointerAtAddress(op.addr); err != nil {
				b.Fatalf("get slid pointer: %v", err)
			}
		}
	})

	b.Run("SlidePointer", func(b *testing.B) {
		mf.ResetFixupsCache()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			op := ops[i%len(ops)]
			_ = mf.SlidePointer(op.raw)
		}
	})
}
