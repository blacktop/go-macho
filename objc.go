package macho

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/blacktop/go-macho/internal/objcreader"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

var ErrObjcSectionNotFound = objcreader.ErrObjcSectionNotFound
var ErrObjcSectionNEmpty = objcreader.ErrObjcSectionNEmpty
var ErrObjcFragileRuntimeUnsupported = objcreader.ErrObjcFragileRuntimeUnsupported

// ErrObjCSelectorBaseUnavailable indicates that relative method selectors need
// the shared cache's selector-string table, which is unavailable in this image.
var ErrObjCSelectorBaseUnavailable = objcreader.ErrObjCSelectorBaseUnavailable

func (f *File) objcReader() *objcreader.Reader {
	f.objcOnce.Do(func() { f.objc = objcreader.New(objcSource{f}) })
	return f.objc
}

func (f *File) PutObjC(addr uint64, obj any) {
	f.objcReader().PutObjC(addr, obj)
}

func (f *File) GetObjC(addr uint64) (any, bool) {
	return f.objcReader().GetObjC(addr)
}

// HasObjC returns true if MachO contains Objective-C metadata.
func (f *File) HasObjC() bool {
	return f.objcReader().HasObjC()
}

// HasPlusLoadMethod returns true if MachO contains a __objc_nlclslist or __objc_nlcatlist section
func (f *File) HasPlusLoadMethod() bool {
	return f.objcReader().HasPlusLoadMethod()
}

// HasObjCMessageReferences returns true if MachO contains a __objc_msgrefs section
func (f *File) HasObjCMessageReferences() bool {
	return f.objcReader().HasObjCMessageReferences()
}

// GetObjCToc returns a table of contents of the ObjC objects in the MachO
func (f *File) GetObjCToc() objc.Toc {
	return f.objcReader().GetObjCToc()
}

// GetObjCImageInfo returns the parsed __objc_imageinfo data
func (f *File) GetObjCImageInfo() (*objc.ImageInfo, error) {
	return f.objcReader().GetObjCImageInfo()
}

// GetObjCClassInfo returns the ClassRO64 (class_ro_t) for a given virtual memory address
func (f *File) GetObjCClassInfo(vmaddr uint64) (*objc.ClassRO64, error) {
	return f.objcReader().GetObjCClassInfo(vmaddr)
}

// GetObjCClassNames returns a map of section data virtual memory address to their class names
func (f *File) GetObjCClassNames() (map[uint64]string, error) {
	return f.objcReader().GetObjCClassNames()
}

// GetObjCMethodNames returns a map of section data virtual memory addresses to their method names
func (f *File) GetObjCMethodNames() (map[uint64]string, error) {
	return f.objcReader().GetObjCMethodNames()
}

// GetObjCClasses returns an array of Objective-C classes
func (f *File) GetObjCClasses() ([]objc.Class, error) {
	return f.objcReader().GetObjCClasses()
}

// GetObjCNonLazyClasses returns an array of Objective-C classes that implement +load
func (f *File) GetObjCNonLazyClasses() ([]objc.Class, error) {
	return f.objcReader().GetObjCNonLazyClasses()
}

// GetObjCClass parses an Objective-C class at a given virtual memory address
func (f *File) GetObjCClass(vmaddr uint64) (*objc.Class, error) {
	return f.objcReader().GetObjCClass(vmaddr)
}

// GetObjCClass2 parses an Objective-C class at a given virtual memory address.
func (f *File) GetObjCClass2(vmaddr uint64) (*objc.Class, error) {
	return f.objcReader().GetObjCClass2(vmaddr)
}

// GetObjCCategories returns an array of Objective-C categories by parsing the __objc_catlist data
func (f *File) GetObjCCategories() ([]objc.Category, error) {
	return f.objcReader().GetObjCCategories()
}

// GetObjCNonLazyCategories returns an array of Objective-C classes that implement +load
func (f *File) GetObjCNonLazyCategories() ([]objc.Category, error) {
	return f.objcReader().GetObjCNonLazyCategories()
}

// ObjCSelectorBaseUnavailable reports whether ObjC parsing encountered a
// relative method list whose selectors are offsets into the shared cache's
// global selector-string table. That table is absent when a dylib is parsed in
// isolation (e.g. extracted from a dyld_shared_cache), so such method names
// cannot be resolved without the full cache. See [ErrObjCSelectorBaseUnavailable].
func (f *File) ObjCSelectorBaseUnavailable() bool {
	return f.objcReader().ObjCSelectorBaseUnavailable()
}

// GetObjCProtocols returns locally readable Objective-C protocol definitions.
// Unavailable external references are skipped; truncated records return an error.
func (f *File) GetObjCProtocols() ([]objc.Protocol, error) {
	return f.objcReader().GetObjCProtocols()
}

func (f *File) GetObjCMethods(vmaddr uint64) ([]objc.Method, error) {
	return f.objcReader().GetObjCMethods(vmaddr)
}

// GetObjCMethodLists parses the method lists in the __objc_methlist section
func (f *File) GetObjCMethodLists() ([]objc.Method, error) {
	return f.objcReader().GetObjCMethodLists()
}

// GetObjCIvars returns the Objective-C instance variables
func (f *File) GetObjCIvars(vmaddr uint64) ([]objc.Ivar, error) {
	return f.objcReader().GetObjCIvars(vmaddr)
}

// GetObjCProperties returns the Objective-C properties
func (f *File) GetObjCProperties(vmaddr uint64) ([]objc.Property, error) {
	return f.objcReader().GetObjCProperties(vmaddr)
}

// GetObjCClassReferences returns a map of classes to their section data virtual memory address
func (f *File) GetObjCClassReferences() (map[uint64]*objc.Class, error) {
	return f.objcReader().GetObjCClassReferences()
}

// GetObjCSuperReferences returns a map of super classes to their section data virtual memory
// address
func (f *File) GetObjCSuperReferences() (map[uint64]*objc.Class, error) {
	return f.objcReader().GetObjCSuperReferences()
}

// GetObjCProtoReferences maps each protocol-reference slot to its protocol.
// It returns an error if a referenced protocol is unavailable or truncated.
func (f *File) GetObjCProtoReferences() (map[uint64]*objc.Protocol, error) {
	return f.objcReader().GetObjCProtoReferences()
}

// GetObjCSelectorReferences returns a map of selector names to their section data virtual
// memory address
func (f *File) GetObjCSelectorReferences() (map[uint64]*objc.Selector, error) {
	return f.objcReader().GetObjCSelectorReferences()
}

// GetCFStrings returns the Objective-C CFStrings
func (f *File) GetCFStrings() ([]objc.CFString, error) {
	return f.objcReader().GetCFStrings()
}

// GetObjCIntObj parses the __objc_intobj section and returns a map of
func (f *File) GetObjCIntegerObjects() (map[uint64]*objc.IntObj, error) {
	return f.objcReader().GetObjCIntegerObjects()
}

// GetObjCStubs returns the Objective-C stubs
func (f *File) GetObjCStubs(
	parse func(uint64, []byte) (map[uint64]*objc.Stub, error),
) (map[uint64]*objc.Stub, error) {
	return f.objcReader().GetObjCStubs(parse)
}

// objcSource adapts File without exposing parser-only services as public methods.
type objcSource struct{ *File }

func (s objcSource) ByteOrder() binary.ByteOrder   { return s.File.ByteOrder }
func (s objcSource) DataReader() types.MachoReader { return s.cr }
func (s objcSource) Sections() []*types.Section    { return s.File.Sections }
func (s objcSource) SegmentNames() []string {
	count := 0
	for _, load := range s.Loads {
		if _, ok := load.(*Segment); ok {
			count++
		}
	}
	names := make([]string, 0, count)
	for _, load := range s.Loads {
		if segment, ok := load.(*Segment); ok {
			names = append(names, segment.Name)
		}
	}
	return names
}
func (s objcSource) PointerSize() uint64 { return s.pointerSize() }
func (s objcSource) RelativeSelectorBase() uint64 {
	return s.sharedCacheRelativeSelectorBaseVMAddress
}
func (s objcSource) ConvertPointer(value uint64) uint64     { return s.vma.Convert(value) }
func (s objcSource) CheckFileData(addr, size uint64) error  { return s.checkFileData(addr, size) }
func (s objcSource) HasFileData(addr, size uint64) bool     { return s.hasFileData(addr, size) }
func (s objcSource) HasZeroFillData(addr, size uint64) bool { return s.hasZeroFillData(addr, size) }
func (s objcSource) AddressResolvable(addr uint64) bool     { return s.addrResolvable(addr) }
func (s objcSource) GetUTF16String(addr, count uint64) (string, error) {
	return s.getUTF16String(addr, count)
}
func (s objcSource) CStringUnavailable(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, ErrCStringNoTerminator) ||
		errors.Is(err, ErrCStringNotFound)
}

func (s objcSource) BindInfoUnavailable(err error) bool {
	return errors.Is(err, ErrMachONoBindInfo)
}
func (s objcSource) SwiftSymbolicName(addr uint64) (string, error) {
	return s.swiftSymbolicName(addr)
}
func (s objcSource) SwiftASCIITypeGuess(addr uint64) (string, bool) {
	return s.swiftASCIITypeGuess(addr)
}
func (s objcSource) SwiftFieldTypesForClass(name string) (map[string]string, error) {
	return s.swiftFieldTypesForClass(name)
}
func (s objcSource) SymbolicMangledNameStringRef(addr uint64) (string, error) {
	return s.makeSymbolicMangledNameStringRef(addr)
}
