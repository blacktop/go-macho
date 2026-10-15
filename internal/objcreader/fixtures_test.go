package objcreader_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

type objcTestSection struct{ seg, name string }

func newFixtureFile(t *testing.T, data []byte, config ...macho.FileConfig) *macho.File {
	t.Helper()
	header := types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_EXECUTE,
	}
	header.Put(data, binary.LittleEndian)
	f, err := macho.NewFile(bytes.NewReader(data), config...)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func newObjCTestFile(t *testing.T, data []byte, defs ...objcTestSection) *macho.File {
	t.Helper()
	if len(data) == 0 {
		data = make([]byte, types.FileHeaderSize64)
	}
	f := newFixtureFile(t, data)
	for _, def := range defs {
		if f.Segment(def.seg) == nil {
			f.AddSegment(&macho.Segment{SegmentHeader: macho.SegmentHeader{
				LoadCmd: types.LC_SEGMENT_64, Name: def.seg,
			}})
		}
		f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
			Seg: def.seg, Name: def.name,
		}})
	}
	return f
}

func reopenFixture(
	t *testing.T, f *macho.File, data []byte, config ...macho.FileConfig,
) *macho.File {
	t.Helper()
	next := newFixtureFile(t, data, config...)
	next.FileTOC = f.FileTOC
	return next
}

func fixtureReader(f *macho.File, data []byte) types.MachoReader {
	vma := &types.VMAddrConverter{VMAddr2Offet: f.GetOffset}
	return types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, int64(len(data)))
}

func identityReader(data []byte) types.MachoReader {
	vma := &types.VMAddrConverter{
		VMAddr2Offet: func(addr uint64) (uint64, error) { return addr, nil },
	}
	return types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, int64(len(data)))
}

func writeLETestData(t *testing.T, dst []byte, values ...any) {
	t.Helper()
	var buf bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&buf, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	copy(dst, buf.Bytes())
}
