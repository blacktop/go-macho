package cpio

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
)

const (
	Magic   = "070707"
	Trailer = "TRAILER!!!"
	hdrSize = 76
)

// https://www.mkssoftware.com/docs/man4/cpio.4.asp
type Header struct {
	Magic    [6]byte
	Dev      [6]byte
	Ino      [6]byte
	Mode     [6]byte
	UID      [6]byte
	GID      [6]byte
	NLink    [6]byte
	RDev     [6]byte
	MTime    [11]byte
	NameSize [6]byte
	FileSize [11]byte
}

type FileInfo struct {
	DeviceNo uint64
	Inode    uint64
	Mode     fs.FileMode
	Uid      int
	Gid      int
	NLink    int
	RDev     int
	Mtime    time.Time
}

type File struct {
	Info FileInfo
	Name string
	Size int64

	offset int64
	length int64
	heap   io.ReaderAt
}

type Reader struct {
	Files map[string]*File

	r          io.ReaderAt
	size       int64
	heapOffset int64
}

// A ReadCloser is a [Reader] that must be closed when no longer needed.
type ReadCloser struct {
	f *os.File
	Reader
}

// OpenReader will open the CPIO file specified by name and return a Reader.
func Open(name string) (*ReadCloser, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	r := new(ReadCloser)
	if err = r.init(f, fi.Size()); err != nil {
		f.Close()
		return nil, err
	}
	r.f = f
	return r, err
}

// NewReader will create a new Reader from the given io.ReaderAt and size.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	if size < 0 {
		return nil, fmt.Errorf("cpio: size cannot be negative")
	}
	cr := new(Reader)
	var err error
	if err = cr.init(r, size); err != nil {
		return nil, err
	}
	return cr, err
}

func (r *ReadCloser) Close() error {
	if r.f != nil {
		return r.f.Close()
	}
	return nil
}

// allOctal reports whether x is entirely ASCII octal digits.
func allOctal(x []byte) bool {
	for _, b := range x {
		if b < '0' || '7' < b {
			return false
		}
	}
	return true
}

// parseOctal converts an octal byte slice to uint64
func parseOctal(b []byte) uint64 {
	var sum uint64
	for _, c := range b {
		if c == 0 {
			break
		}
		sum = sum*8 + uint64(c-'0')
	}
	return sum
}

func (r *Reader) init(rdr io.ReaderAt, size int64) error {
	r.r = rdr
	r.size = size
	r.Files = make(map[string]*File)

	var offset int64
	for {
		// Read header
		var header Header
		err := binary.Read(io.NewSectionReader(r.r, offset, hdrSize), binary.BigEndian, &header)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		offset += hdrSize

		// Verify magic number and header fields are valid octal
		if !allOctal(header.Magic[:]) || string(header.Magic[:]) != Magic {
			return fmt.Errorf("cpio: invalid magic number: %s", string(header.Magic[:]))
		}

		// Parse header fields
		nameSize := parseOctal(header.NameSize[:])
		fileSize := parseOctal(header.FileSize[:])

		// Validate sizes
		if nameSize == 0 {
			return fmt.Errorf("cpio: invalid name size")
		}
		if offset+int64(nameSize) > size {
			return fmt.Errorf("cpio: name too long")
		}

		// Read filename
		nameBuf := make([]byte, nameSize)
		if _, err := r.r.ReadAt(nameBuf, offset); err != nil {
			return err
		}
		offset += int64(nameSize)
		name := string(nameBuf[:nameSize-1]) // Remove null terminator

		// Check for trailer
		// The MKS cpio page says "TRAILER!!"
		// but the Apple pkg files use "TRAILER!!!".
		if name == Trailer {
			break
		}

		mode := parseOctal(header.Mode[:])
		fmode := fs.FileMode(mode & 0777)
		if mode&040000 != 0 {
			fmode |= fs.ModeDir
		}

		if fmode&fs.ModeDir != 0 {
			r.heapOffset = offset
			continue
		}

		// Add to files map using inode as key
		r.Files[strings.TrimPrefix(name, ".")] = &File{
			Info: FileInfo{
				DeviceNo: parseOctal(header.Dev[:]),
				Inode:    parseOctal(header.Ino[:]),
				Mode:     fmode,
				Uid:      int(parseOctal(header.UID[:])),
				Gid:      int(parseOctal(header.GID[:])),
				NLink:    int(parseOctal(header.NLink[:])),
				RDev:     int(parseOctal(header.RDev[:])),
				Mtime:    time.Unix(int64(int64(parseOctal(header.MTime[:]))), 0),
			},
			Name:   strings.TrimPrefix(name, "."),
			Size:   int64(fileSize),
			offset: offset,
			length: int64(fileSize),
			heap:   r.r,
		}

		// Move to next file
		offset += int64(fileSize)
		r.heapOffset = offset
	}

	return nil
}

func (f *File) OpenRaw() (*io.SectionReader, error) {
	if f.heap == nil {
		return nil, fmt.Errorf("cpio: file has no heap")
	}
	return io.NewSectionReader(f.heap, f.offset, f.length), nil
}

// Multiple files may be read concurrently.
func (f *File) Open() (io.ReadCloser, error) {
	if f.heap == nil {
		return nil, fmt.Errorf("cpio: file has no heap")
	}

	return &fileReader{
		f:      f,
		offset: 0,
	}, nil
}

type fileReader struct {
	f      *File
	offset int64
}

func (fr *fileReader) Read(p []byte) (n int, err error) {
	if fr.offset >= fr.f.length {
		return 0, io.EOF
	}

	n = int(fr.f.length - fr.offset)
	if len(p) < n {
		n = len(p)
	}

	if _, err := fr.f.heap.ReadAt(p[:n], fr.f.offset+fr.offset); err != nil {
		return 0, err
	}

	fr.offset += int64(n)
	return n, nil
}

func (fr *fileReader) Close() error {
	return nil
}
