package objcreader_test

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

func TestObjCClassListCacheUsesVMAddress(t *testing.T) {
	f, data := issue93SelectionFixture(t)
	const raw = uint64(0x990000)
	f.Section("__DATA", "__objc_classlist").Size = 16
	writeLETestData(t, data[0x1090:], raw, raw)
	conversions := 0
	f = reopenFixture(t, f, data, macho.FileConfig{VMAddrConverter: types.VMAddrConverter{
		Converter: func(value uint64) uint64 {
			if value == raw {
				conversions++
				return 0x2600
			}
			if value == 0x2600 {
				return 0x5000
			}
			return value
		},
	}})
	issue93SelectionExpect(t, f, "Ordinary", "Ordinary", "_TtC5Child4Leaf")
	if class, ok := f.GetObjC(0x2600); !ok || class.(*objc.Class).Name != "Ordinary" {
		t.Fatalf("missing canonical class cache entry: %v, %t", class, ok)
	}
	if _, ok := f.GetObjC(raw); ok || conversions != 2 {
		t.Fatalf("raw cache entry=%t, pointer conversions=%d", ok, conversions)
	}
}

func unavailableClassFixture(t *testing.T) (*macho.File, []byte) {
	t.Helper()
	f, data := issue93SelectionFixture(t)
	f.Segment("__DATA").Filesz = 0x900
	writeLETestData(t, data[0x1900:], objc.ObjcClass64{DataVMAddrAndFastFlags: 0x2a00})
	writeLETestData(t, data[0x1a00:], objc.ClassRO64{Flags: objc.RO_ROOT, NameVMAddr: 0x15a0})
	return f, data
}

func TestObjCCategoryDoesNotCacheUnavailableClass(t *testing.T) {
	f, data := unavailableClassFixture(t)
	f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
		Seg: "__DATA", Name: "__objc_catlist", Addr: 0x20c0, Size: 8,
	}})
	writeLETestData(t, data[0x10c0:], uint64(0x2800))
	writeLETestData(t, data[0x1800:], objc.CategoryT{NameVMAddr: 0x15a0, ClsVMAddr: 0x2900})
	categories, err := f.GetObjCCategories()
	if err != nil || len(categories) != 1 || categories[0].Class == nil {
		t.Fatalf("categories=%v error=%v", categories, err)
	}
	checkRecoveredClass(t, f, (*macho.File).GetObjCClass)
}

func checkRecoveredClass(
	t *testing.T, f *macho.File, read func(*macho.File, uint64) (*objc.Class, error),
) {
	t.Helper()
	if value, ok := f.GetObjC(0x2900); ok {
		t.Fatalf("unavailable class polluted the cache: %#v", value)
	}
	f.Segment("__DATA").Filesz = 0x1000
	class, err := read(f, 0x2900)
	if err != nil || class == nil || class.Name != "Ordinary" {
		t.Fatalf("recovered class=%v error=%v", class, err)
	}
}

func TestObjCClassDoesNotCacheUnavailableRelations(t *testing.T) {
	for _, read := range []struct {
		name string
		call func(*macho.File, uint64) (*objc.Class, error)
	}{
		{"class", (*macho.File).GetObjCClass},
		{"class2", (*macho.File).GetObjCClass2},
	} {
		for _, field := range []struct {
			name   string
			offset int
		}{{"isa", 0}, {"superclass", 8}} {
			t.Run(read.name+"/"+field.name, func(t *testing.T) {
				f, data := unavailableClassFixture(t)
				binary.LittleEndian.PutUint32(data[0x1700:], 0)
				binary.LittleEndian.PutUint64(data[0x1600+field.offset:], 0x2900)
				if _, err := read.call(f, 0x2600); err != nil {
					t.Fatal(err)
				}
				checkRecoveredClass(t, f, read.call)
			})
		}
	}
}

func TestObjCCacheConcurrentReferences(t *testing.T) {
	f, data := issue93SelectionFixture(t)
	f.AddSection(&types.Section{SectionHeader: types.SectionHeader{
		Seg: "__DATA", Name: "__objc_classrefs", Addr: 0x20c0, Size: 8,
	}})
	writeLETestData(t, data[0x10c0:], uint64(0x2600))
	class := &objc.Class{Name: "Ordinary"}
	f.PutObjC(0x2600, class)
	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				f.PutObjC(0x2600, class)
			}
		}
	}()
	defer func() { close(stop); writers.Wait() }()
	for i := 0; i < 100; i++ {
		refs, err := f.GetObjCClassReferences()
		if err != nil || refs[0x20c0] != class {
			t.Fatalf("references=%v error=%v", refs, err)
		}
	}
}
