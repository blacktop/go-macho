package objcreader_test

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/internal/objcreader"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

// The callback contract is internal, so these two tests supply its reader directly.
type methodSource struct {
	objcreader.Source
	file *macho.File
	data []byte
	read types.MachoReader
}

func newMethodReader(f *macho.File, data []byte) *objcreader.Reader {
	return objcreader.New(methodSource{file: f, data: data, read: fixtureReader(f, data)})
}

func (s methodSource) ByteOrder() binary.ByteOrder            { return s.file.ByteOrder }
func (s methodSource) DataReader() types.MachoReader          { return s.read }
func (s methodSource) RelativeSelectorBase() uint64           { return 0 }
func (s methodSource) ConvertPointer(addr uint64) uint64      { return s.file.SlidePointer(addr) }
func (s methodSource) GetCString(addr uint64) (string, error) { return s.file.GetCString(addr) }
func (s methodSource) GetPointerAtAddress(addr uint64) (uint64, error) {
	return s.file.GetPointerAtAddress(addr)
}

func (s methodSource) CheckFileData(addr, size uint64) error {
	off, err := s.file.GetOffset(addr)
	if err != nil {
		return err
	}
	if off > uint64(len(s.data)) || size > uint64(len(s.data))-off {
		return io.EOF
	}
	return nil
}

func TestForEachObjCMethodDirectSelectorsWithoutBase(t *testing.T) {
	f, data := newResilientObjCTestFile(t)
	const addr = uint64(0x2500)
	writeLETestData(t, data[0x1500:], uint32(1<<31|1<<30|12), uint32(0))
	r := newMethodReader(f, data)
	if err := r.ForEachMethod(addr, func(uint64, objc.Method, *bool) {
		t.Fatal("empty method list called its handler")
	}); err != nil {
		t.Fatalf("empty method list: %v", err)
	}
	if r.ObjCSelectorBaseUnavailable() {
		t.Fatal("empty method list required a selector base")
	}
	binary.LittleEndian.PutUint32(data[0x1504:], 1)
	called := false
	err := r.ForEachMethod(addr, func(uint64, objc.Method, *bool) { called = true })
	if !errors.Is(err, macho.ErrObjCSelectorBaseUnavailable) {
		t.Fatalf("ForEachMethod() error = %v", err)
	}
	if !r.ObjCSelectorBaseUnavailable() || called {
		t.Fatalf("selector base unavailable=%t, handler called=%t",
			r.ObjCSelectorBaseUnavailable(), called)
	}
	if _, err := f.GetObjCMethods(addr); err == nil || !f.ObjCSelectorBaseUnavailable() {
		t.Fatalf("public method reader did not report the missing selector base: %v", err)
	}
}

func TestObjCMethodEntryAddresses(t *testing.T) {
	for _, relative := range []bool{false, true} {
		f, data := newResilientObjCTestFile(t)
		if relative {
			writeLETestData(t, data[0x1500:], uint32(1<<31|12), uint32(1),
				int32(0x1600-0x2508), int32(0x1490-0x250c), int32(0x1500-0x2510))
			writeLETestData(t, data[0x600:], uint64(0x1470))
		}
		var addresses []uint64
		err := newMethodReader(f, data).ForEachMethod(0x2500,
			func(addr uint64, _ objc.Method, _ *bool) { addresses = append(addresses, addr) })
		if err != nil || len(addresses) != 1 || addresses[0] != 0x2508 {
			t.Fatalf("relative=%t addresses=%#x error=%v", relative, addresses, err)
		}
	}
}
