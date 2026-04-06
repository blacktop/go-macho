package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/blacktop/go-macho/types"
)

type recordingCacheReader struct {
	addrBase      uint64
	addrData      []byte
	offsetData    []byte
	readAtOffsets []int64
	readAtAddrs   []uint64
}

func (r *recordingCacheReader) Read([]byte) (int, error) {
	return 0, errors.New("unexpected Read")
}

func (r *recordingCacheReader) Seek(int64, int) (int64, error) {
	return 0, errors.New("unexpected Seek")
}

func (r *recordingCacheReader) SeekToAddr(uint64) error {
	return errors.New("unexpected SeekToAddr")
}

func (r *recordingCacheReader) ReadAt(p []byte, off int64) (int, error) {
	r.readAtOffsets = append(r.readAtOffsets, off)
	return readSliceAt(p, r.offsetData, off)
}

func (r *recordingCacheReader) ReadAtAddr(p []byte, addr uint64) (int, error) {
	r.readAtAddrs = append(r.readAtAddrs, addr)
	if addr < r.addrBase {
		return 0, io.EOF
	}
	return readSliceAt(p, r.addrData, int64(addr-r.addrBase))
}

func readSliceAt(dst []byte, src []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(src)) {
		return 0, io.EOF
	}
	n := copy(dst, src[off:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

func TestNewFileSectionDataUsesReadAtAddr(t *testing.T) {
	t.Parallel()

	const (
		sectionAddr   = 0x4000
		sectionSize   = 4
		sectionOffset = 0x180
	)

	tests := []struct {
		name  string
		build func(addr uint64, size uint64, offset uint32) ([]byte, error)
	}{
		{name: "segment32", build: buildSyntheticSectionMacho32},
		{name: "segment64", build: buildSyntheticSectionMacho64},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw, err := tt.build(sectionAddr, sectionSize, sectionOffset)
			if err != nil {
				t.Fatalf("build synthetic Mach-O: %v", err)
			}

			cache := &recordingCacheReader{
				addrBase:   sectionAddr,
				addrData:   []byte{0xde, 0xad, 0xbe, 0xef},
				offsetData: bytes.Repeat([]byte{0xaa}, int(sectionOffset)+sectionSize),
			}

			f, err := NewFile(bytes.NewReader(raw), FileConfig{
				CacheReader: cache,
			})
			if err != nil {
				t.Fatalf("NewFile() error = %v", err)
			}

			if len(cache.readAtAddrs) != 0 {
				t.Fatalf("NewFile() unexpectedly used ReadAtAddr during parse: %v", cache.readAtAddrs)
			}
			if len(f.Sections) != 1 {
				t.Fatalf("len(Sections) = %d, want 1", len(f.Sections))
			}

			got, err := f.Sections[0].Data()
			if err != nil {
				t.Fatalf("Section.Data() error = %v", err)
			}

			want := []byte{0xde, 0xad, 0xbe, 0xef}
			if !bytes.Equal(got, want) {
				t.Fatalf("Section.Data() = %x, want %x", got, want)
			}
			if len(cache.readAtOffsets) != 0 {
				t.Fatalf("Section.Data() unexpectedly used offset-based ReadAt: %v", cache.readAtOffsets)
			}
			if len(cache.readAtAddrs) != 1 || cache.readAtAddrs[0] != sectionAddr {
				t.Fatalf("Section.Data() ReadAtAddr calls = %v, want [%#x]", cache.readAtAddrs, sectionAddr)
			}
		})
	}
}

func buildSyntheticSectionMacho32(addr uint64, size uint64, offset uint32) ([]byte, error) {
	var segName [16]byte
	var secName [16]byte

	copy(segName[:], "__TEXT")
	copy(secName[:], "__text")

	segmentSize := uint32(binary.Size(types.Segment32{}) + binary.Size(types.Section32{}))

	return buildSyntheticSectionMacho(
		types.FileHeader{
			Magic:        types.Magic32,
			CPU:          types.CPUI386,
			Type:         types.MH_EXECUTE,
			NCommands:    1,
			SizeCommands: segmentSize,
		},
		types.Segment32{
			LoadCmd: types.LC_SEGMENT,
			Len:     segmentSize,
			Name:    segName,
			Addr:    uint32(addr),
			Memsz:   uint32(size),
			Offset:  offset,
			Filesz:  uint32(size),
			Maxprot: 7,
			Prot:    5,
			Nsect:   1,
		},
		types.Section32{
			Name:   secName,
			Seg:    segName,
			Addr:   uint32(addr),
			Size:   uint32(size),
			Offset: offset,
		},
	)
}

func buildSyntheticSectionMacho64(addr uint64, size uint64, offset uint32) ([]byte, error) {
	var segName [16]byte
	var secName [16]byte

	copy(segName[:], "__TEXT")
	copy(secName[:], "__text")

	segmentSize := uint32(binary.Size(types.Segment64{}) + binary.Size(types.Section64{}))

	return buildSyntheticSectionMacho(
		types.FileHeader{
			Magic:        types.Magic64,
			CPU:          types.CPUArm64,
			Type:         types.MH_EXECUTE,
			NCommands:    1,
			SizeCommands: segmentSize,
		},
		types.Segment64{
			LoadCmd: types.LC_SEGMENT_64,
			Len:     segmentSize,
			Name:    segName,
			Addr:    addr,
			Memsz:   size,
			Offset:  uint64(offset),
			Filesz:  size,
			Maxprot: 7,
			Prot:    5,
			Nsect:   1,
		},
		types.Section64{
			Name:   secName,
			Seg:    segName,
			Addr:   addr,
			Size:   size,
			Offset: offset,
		},
	)
}

func buildSyntheticSectionMacho(header types.FileHeader, segment any, section any) ([]byte, error) {
	var buf bytes.Buffer

	headerBuf := make([]byte, types.FileHeaderSize64)
	headerSize := header.Put(headerBuf, binary.LittleEndian)
	if _, err := buf.Write(headerBuf[:headerSize]); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, segment); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, section); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
