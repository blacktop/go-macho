// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/blacktop/go-macho/internal/saferio"
	"github.com/blacktop/go-macho/types"
)

const (
	alignBits = 14
	align     = 1 << alignBits
)

// A FatFile is a Mach-O universal binary that contains at least one architecture.
type FatFile struct {
	FatHeader
	closer io.Closer
}

type FatHeader struct {
	Magic  types.Magic
	Count  uint32
	Arches []FatArch
}

// A FatArchHeader represents a fat header for a specific image architecture.
type FatArchHeader struct {
	CPU    types.CPU
	SubCPU types.CPUSubtype
	Offset uint32
	Size   uint32
	Align  uint32
}

const fatArchHeaderSize = 5 * 4

// fatArch64Header is the on-disk fat header of an image in a universal binary
// with the MagicFat64 magic number (fat_arch_64).
type fatArch64Header struct {
	CPU      types.CPU
	SubCPU   types.CPUSubtype
	Offset   uint64
	Size     uint64
	Align    uint32
	Reserved uint32
}

const fatArch64HeaderSize = 2*4 + 2*8 + 2*4

// A FatArch is a Mach-O File inside a FatFile.
type FatArch struct {
	// FatArchHeader describes the image in either format. Its Offset and
	// Size are the image's unless the file was opened with
	// FatConfig.LargeImages, in which case one that does not fit in 32 bits
	// is zero; Offset64 and Size64 always hold them.
	FatArchHeader
	Offset64 uint64
	Size64   uint64
	*File
	data []byte
}

// ErrNotFat is returned from NewFatFile or OpenFat when the file is not a
// universal binary but may be a thin binary, based on its magic number.
var ErrNotFat = &FormatError{0, "not a fat Mach-O file", nil}

// FatConfig configures how NewFatFile and OpenFat read a universal binary.
type FatConfig struct {
	// LargeImages allows a MagicFat64 file to hold images whose offset or
	// size does not fit in 32 bits. Callers that set it must use
	// FatArch.Offset64 and FatArch.Size64 rather than Offset and Size.
	// Without it, such a file is rejected with a FormatError, so that code
	// reading only the 32-bit fields never sees truncated values.
	LargeImages bool
}

// NewFatFile creates a new FatFile for accessing all the Mach-O images in a
// universal binary. The Mach-O binary is expected to start at position 0 in
// the ReaderAt.
func NewFatFile(r io.ReaderAt, config ...FatConfig) (*FatFile, error) {
	var cfg FatConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	var ff FatFile
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	// Read the fat_header struct, which is always in big endian.
	// Start with the magic number.
	err := binary.Read(sr, binary.BigEndian, &ff.Magic)
	if err != nil {
		return nil, &FormatError{0, "error reading magic number", nil}
	} else if ff.Magic != types.MagicFat && ff.Magic != types.MagicFat64 {
		// See if this is a Mach-O file via its magic number. The magic
		// must be converted to little endian first though.
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], ff.Magic.Int())
		leMagic := binary.LittleEndian.Uint32(buf[:])
		if leMagic == types.Magic32.Int() || leMagic == types.Magic64.Int() {
			return nil, ErrNotFat
		}
		return nil, &FormatError{0, "invalid magic number", nil}

	}
	offset := int64(4)

	// Read the number of fat_arch (or fat_arch_64) headers that come after the fat_header.
	var narch uint32
	err = binary.Read(sr, binary.BigEndian, &narch)
	if err != nil {
		return nil, &FormatError{offset, "invalid fat_header", nil}
	}
	offset += 4

	if narch < 1 {
		return nil, &FormatError{offset, "file contains no images", nil}
	}

	// Combine the Cpu and SubCpu (both uint32) into a uint64 to make sure
	// there are not duplicate architectures.
	seenArches := make(map[uint64]bool)
	// Make sure that all images are for the same MH_ type.
	var machoType types.HeaderFileType

	// Following the fat_header comes narch fat_arch (or, for MagicFat64,
	// fat_arch_64) structs that index Mach-O images further in the file.
	c := saferio.SliceCap[FatArch](uint64(narch))
	if c < 0 {
		return nil, &FormatError{offset, "too many images", nil}
	}
	ff.Arches = make([]FatArch, 0, c)
	archSize, archName := int64(fatArchHeaderSize), "fat_arch"
	if ff.Magic == types.MagicFat64 {
		archSize, archName = fatArch64HeaderSize, "fat_arch_64"
	}
	for i := uint32(0); i < narch; i++ {
		fa, err := readFatArch(sr, ff.Magic)
		if err != nil {
			return nil, &FormatError{offset, "invalid " + archName + " header", nil}
		}
		if fa.Offset64 > 1<<63-1 || fa.Size64 > 1<<63-1-fa.Offset64 {
			return nil, &FormatError{offset, "fat_arch_64 image out of range", nil}
		}
		if !cfg.LargeImages && (fa.Offset64 > 1<<32-1 || fa.Size64 > 1<<32-1) {
			return nil, &FormatError{offset, "fat_arch_64 image offset or size does not fit in 32 bits (set FatConfig.LargeImages to read it)", nil}
		}
		// An io.ReaderAt has no length, so read the image's last byte to
		// check that the image lies within the file.
		if fa.Size64 > 0 {
			var last [1]byte
			if n, _ := r.ReadAt(last[:], int64(fa.Offset64+fa.Size64-1)); n != 1 {
				return nil, &FormatError{offset, "fat image extends past end of file", nil}
			}
		}
		offset += archSize

		fr := io.NewSectionReader(r, int64(fa.Offset64), int64(fa.Size64))
		fa.File, err = NewFile(fr)
		if err != nil {
			return nil, err
		}

		// Make sure the architecture for this image is not duplicate.
		seenArch := (uint64(fa.CPU) << 32) | uint64(fa.SubCPU)
		if o, k := seenArches[seenArch]; o || k {
			return nil, &FormatError{offset, fmt.Sprintf("duplicate architecture cpu=%v, subcpu=%#x", fa.CPU, fa.SubCPU), nil}
		}
		seenArches[seenArch] = true

		// Make sure the Mach-O type matches that of the first image.
		if i == 0 {
			machoType = fa.Type
		} else {
			if fa.Type != machoType {
				return nil, &FormatError{offset, fmt.Sprintf("Mach-O type for architecture #%d (type=%#x) does not match first (type=%#x)", i, fa.Type, machoType), nil}
			}
		}
		ff.Arches = append(ff.Arches, fa)
	}

	return &ff, nil
}

// readFatArch reads the next fat_arch or fat_arch_64 into a FatArch.
func readFatArch(r io.Reader, magic types.Magic) (fa FatArch, err error) {
	if magic != types.MagicFat64 {
		err = binary.Read(r, binary.BigEndian, &fa.FatArchHeader)
		fa.setRange(uint64(fa.Offset), uint64(fa.Size))
		return fa, err
	}
	var h fatArch64Header
	err = binary.Read(r, binary.BigEndian, &h)
	fa.FatArchHeader = FatArchHeader{CPU: h.CPU, SubCPU: h.SubCPU, Align: h.Align}
	fa.setRange(h.Offset, h.Size)
	return fa, err
}

// setRange sets the image's offset and size: always in Offset64 and Size64,
// and in the 32-bit Offset and Size where they fit, which are otherwise zero.
func (fa *FatArch) setRange(offset, size uint64) {
	fa.Offset64, fa.Size64 = offset, size
	fa.Offset, fa.Size = 0, 0
	if offset <= 1<<32-1 {
		fa.Offset = uint32(offset)
	}
	if size <= 1<<32-1 {
		fa.Size = uint32(size)
	}
}

// OpenFat opens the named file using os.Open and prepares it for use as a Mach-O
// universal binary.
func OpenFat(name string, config ...FatConfig) (*FatFile, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFatFile(f, config...)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

func CreateFat(name string, files ...string) (*FatFile, error) {

	fat := &FatFile{
		FatHeader: FatHeader{
			Magic: types.MagicFat,
		},
	}

	// Lay the images out from their sizes on disk first, so that inputs that
	// cannot fit are rejected before any of them is read.
	offset := int64(align)
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read binary %s: %w", f, err)
		}
		if offset, err = nextFatOffset(f, offset, fi.Size()); err != nil {
			return nil, err
		}
	}

	offset = int64(align)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read binary %s: %w", f, err)
		}
		// The sizes on disk were only a hint: lay out what was read.
		next, err := nextFatOffset(f, offset, int64(len(data)))
		if err != nil {
			return nil, err
		}

		m, err := NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to parse MachO %s: %w", f, err)
		}
		defer m.Close()

		fat.Count++

		fa := FatArch{
			FatArchHeader: FatArchHeader{CPU: m.CPU, SubCPU: m.SubCPU, Align: alignBits},
			File:          m,
			data:          data,
		}
		fa.setRange(uint64(offset), uint64(len(data)))
		fat.Arches = append(fat.Arches, fa)

		offset = next
	}

	out, err := os.Create(name)
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", name, err)
	}
	fat.closer = out

	if err := binary.Write(out, binary.BigEndian, fat.FatHeader.Magic); err != nil {
		return nil, fmt.Errorf("failed to write fat header magic to file: %w", err)
	}
	if err := binary.Write(out, binary.BigEndian, fat.FatHeader.Count); err != nil {
		return nil, fmt.Errorf("failed to write fat header count to file: %w", err)
	}
	for _, farch := range fat.Arches {
		if err := binary.Write(out, binary.BigEndian, farch.FatArchHeader); err != nil {
			return nil, fmt.Errorf("failed to write fat header arch %s header to file: %w", farch.CPU, err)
		}
	}

	offset, _ = out.Seek(0, io.SeekCurrent)

	for _, farch := range fat.Arches {
		if offset < int64(farch.Offset) {
			if _, err := out.Write(make([]byte, int64(farch.Offset)-offset)); err != nil {
				return nil, fmt.Errorf("failed to write to file: %w", err)
			}
			offset = int64(farch.Offset)
		}
		if _, err := out.Write(farch.data); err != nil {
			return nil, fmt.Errorf("failed to write to file: %w", err)
		}
		offset += int64(len(farch.data))
	}

	return fat, nil
}

// nextFatOffset returns the offset of the image that follows one of the given
// size at offset in a 32-bit fat file, or an error if the image, read from
// the file name, does not fit there.
func nextFatOffset(name string, offset, size int64) (int64, error) {
	if offset > 1<<32-1 || size > 1<<32-1 {
		return 0, fmt.Errorf("failed to add %s: image does not fit in a 32-bit fat file", name)
	}
	return int64(types.RoundUp(uint64(offset+size), align)), nil
}

// func (ff *FatFile) Save(name string) error {
// 	return nil
// }

// Close with close the Mach-O Fat file.
func (ff *FatFile) Close() error {
	var err error
	if ff.closer != nil {
		err = ff.closer.Close()
		ff.closer = nil
	}
	return err
}
