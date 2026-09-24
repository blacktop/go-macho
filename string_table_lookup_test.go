package macho

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

const lookupTestFile = "internal/testdata/gcc-amd64-darwin-exec.base64"

// tableLookup serves names from a private copy of the string table it was
// handed, recording every offset NewFile asks for.
type tableLookup struct {
	size    uint64
	offsets []uint64
}

func (l *tableLookup) lookup(ra io.ReaderAt) func(int64, uint64) (func(uint64) string, error) {
	return func(offset int64, size uint64) (func(uint64) string, error) {
		tab := make([]byte, size)
		if _, err := ra.ReadAt(tab, offset); err != nil {
			return nil, err
		}
		l.size = size
		return func(off uint64) string {
			l.offsets = append(l.offsets, off)
			return cstring(tab[off:])
		}, nil
	}
}

func TestStringTableLookup(t *testing.T) {
	want, err := openObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	if want.Symtab == nil || len(want.Symtab.Syms) == 0 {
		t.Fatal("fixture has no symbols")
	}

	ra, err := readerAtFromObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	var l tableLookup
	got, err := NewFile(ra, FileConfig{StringTableLookup: l.lookup(ra)})
	if err != nil {
		t.Fatalf("NewFile with StringTableLookup: %v", err)
	}
	if !reflect.DeepEqual(got.Symtab.Syms, want.Symtab.Syms) {
		t.Errorf("symbols differ with StringTableLookup\n got %+v\nwant %+v", got.Symtab.Syms, want.Symtab.Syms)
	}
	if len(l.offsets) == 0 {
		t.Fatal("lookup was never called")
	}
	for _, off := range l.offsets {
		if off >= l.size {
			t.Errorf("NewFile asked for offset %#x, outside Strsize=%#x", off, l.size)
		}
	}
}

func TestStringTableLookupRejectsOverlongName(t *testing.T) {
	ra, err := readerAtFromObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	// One byte longer than the whole table, so the name is overlong even at
	// offset 0 and the test does not depend on where the fixture's symbols sit.
	overlong := func(offset int64, size uint64) (func(uint64) string, error) {
		return func(off uint64) string { return strings.Repeat("x", int(size)+1) }, nil
	}
	if _, err := NewFile(ra, FileConfig{StringTableLookup: overlong}); err == nil {
		t.Fatal("NewFile accepted a name extending past the string table")
	} else if !strings.Contains(err.Error(), "extends past Strsize") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStringTableLookupDeclines(t *testing.T) {
	want, err := openObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	ra, err := readerAtFromObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	declines := func(int64, uint64) (func(uint64) string, error) { return nil, nil }
	got, err := NewFile(ra, FileConfig{StringTableLookup: declines})
	if err != nil {
		t.Fatalf("NewFile with declining StringTableLookup: %v", err)
	}
	if !reflect.DeepEqual(got.Symtab.Syms, want.Symtab.Syms) {
		t.Errorf("symbols differ when the lookup declines\n got %+v\nwant %+v", got.Symtab.Syms, want.Symtab.Syms)
	}
}

func TestStringTableLookupError(t *testing.T) {
	ra, err := readerAtFromObscured(lookupTestFile)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	failing := func(int64, uint64) (func(uint64) string, error) { return nil, boom }
	if _, err := NewFile(ra, FileConfig{StringTableLookup: failing}); err == nil {
		t.Fatal("NewFile ignored StringTableLookup error")
	} else if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error does not carry the lookup's error: %v", err)
	}
}
