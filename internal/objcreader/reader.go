package objcreader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/blacktop/go-macho/types"
)

// Source supplies the active Mach-O image and its address/Swift decoding services.
// Implementations must expose the live reader and layout rather than a stale snapshot.
type Source interface {
	ByteOrder() binary.ByteOrder
	DataReader() types.MachoReader
	Sections() []*types.Section
	SegmentNames() []string
	Section(string, string) *types.Section
	PointerSize() uint64
	RelativeSelectorBase() uint64
	ConvertPointer(uint64) uint64
	GetOffset(uint64) (uint64, error)
	CheckFileData(uint64, uint64) error
	HasFileData(uint64, uint64) bool
	HasZeroFillData(uint64, uint64) bool
	AddressResolvable(uint64) bool
	GetCString(uint64) (string, error)
	GetUTF16String(uint64, uint64) (string, error)
	CStringUnavailable(error) bool
	GetPointerAtAddress(uint64) (uint64, error)
	GetSlidPointerAtAddress(uint64) (uint64, error)
	GetBindName(uint64) (string, error)
	BindInfoUnavailable(error) bool
	HasFixups() bool
	SwiftSymbolicName(uint64) (string, error)
	SwiftASCIITypeGuess(uint64) (string, bool)
	SwiftFieldTypesForClass(string) (map[string]string, error)
	SymbolicMangledNameStringRef(uint64) (string, error)
}

// Reader parses Objective-C metadata and owns the per-image ObjC cache.
type Reader struct {
	Source
	mu                          sync.Mutex
	objc                        map[uint64]any
	objcRuntimeOnce             sync.Once
	objcHasNonFragileRuntime    bool
	objcHasFragileRuntime       bool
	objcSelectorBaseUnavailable bool
}

// New returns a Reader that parses Objective-C metadata from source.
func New(source Source) *Reader {
	return &Reader{Source: source, objc: make(map[uint64]any)}
}

const sizeOfInt64 = 8

var ErrObjcSectionNotFound = errors.New("missing required ObjC section")

var ErrObjcSectionNEmpty = errors.New("required ObjC section is empty")

var ErrObjcFragileRuntimeUnsupported = errors.New(
	"objective-c fragile runtime metadata is unsupported")

// ErrObjCSelectorBaseUnavailable indicates a relative ObjC method list whose
// selectors are offsets into the shared cache's global selector-string table,
// which is not present when parsing a dylib in isolation (e.g. one extracted
// from a dyld_shared_cache). Such method names can only be resolved against the
// full cache.
var ErrObjCSelectorBaseUnavailable = errors.New(
	"ObjC relative method selectors require the shared cache's selector base, " +
		"which is unavailable in a standalone dylib")

var legacyObjCSectionNames = map[string]struct{}{
	"__image_info":     {},
	"__module_info":    {},
	"__class":          {},
	"__meta_class":     {},
	"__protocol":       {},
	"__protocol_ext":   {},
	"__category":       {},
	"__class_vars":     {},
	"__instance_vars":  {},
	"__cls_refs":       {},
	"__message_refs":   {},
	"__symbols":        {},
	"__sel_refs":       {},
	"__string_object":  {},
	"__class_names":    {},
	"__meth_var_names": {},
	"__meth_var_types": {},
	"__selector_strs":  {},
}

func isLegacyObjCSectionName(name string) bool {
	_, ok := legacyObjCSectionNames[strings.ToLower(name)]
	return ok
}

func (f *Reader) readObjCData(addr uint64, data []byte) error {
	if err := f.CheckFileData(addr, uint64(len(data))); err != nil {
		return err
	}
	return f.readObjCBytes(addr, data)
}

func (f *Reader) readOptionalObjCData(addr uint64, data []byte) (bool, error) {
	if f.CheckFileData(addr, uint64(len(data))) != nil {
		return false, nil
	}
	err := f.readObjCBytes(addr, data)
	return err == nil, err
}

// readObjCBytes requires the caller to validate the complete address range.
func (f *Reader) readObjCBytes(addr uint64, data []byte) error {
	n, err := f.DataReader().ReadAtAddr(data, addr)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (f *Reader) PutObjC(addr uint64, obj any) {
	f.mu.Lock()
	f.objc[addr] = obj
	f.mu.Unlock()
}

func (f *Reader) GetObjC(addr uint64) (any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	val, ok := f.objc[addr]
	return val, ok
}

func (f *Reader) getCStringWithFallback(
	addr uint64, label string, allowSwift bool,
) (string, error) {
	str, err := f.GetCString(addr)
	if err == nil {
		return str, nil
	}
	if f.CStringUnavailable(err) {
		if allowSwift {
			if swiftStr, swiftErr := f.SwiftSymbolicName(addr); swiftErr == nil {
				return swiftStr, nil
			}
			return fmt.Sprintf("@\"SwiftUnresolved_0x%x\"", addr), nil
		}
		return fmt.Sprintf("/* unresolved %s at %#x */", label, addr), nil
	}
	return "", err
}

func (f *Reader) hasObjCNonFragileRuntime() bool {
	f.detectObjCRuntimeKinds()
	return f.objcHasNonFragileRuntime
}

func (f *Reader) hasObjCFragileRuntime() bool {
	f.detectObjCRuntimeKinds()
	return f.objcHasFragileRuntime
}

func (f *Reader) detectObjCRuntimeKinds() {
	f.objcRuntimeOnce.Do(func() {
		for _, sec := range f.Sections() {
			if strings.HasPrefix(sec.Seg, "__DATA") && strings.HasPrefix(sec.Name, "__objc_") {
				f.objcHasNonFragileRuntime = true
			}
			if strings.EqualFold(sec.Seg, "__OBJC") && isLegacyObjCSectionName(sec.Name) {
				f.objcHasFragileRuntime = true
			}
			if f.objcHasNonFragileRuntime && f.objcHasFragileRuntime {
				return
			}
		}
	})
}

func (f *Reader) ensureObjCNonFragileRuntime(api string) error {
	f.detectObjCRuntimeKinds()
	if f.objcHasFragileRuntime && !f.objcHasNonFragileRuntime {
		return fmt.Errorf(
			"%s requires the Objective-C non-fragile runtime: %w",
			api, ErrObjcFragileRuntimeUnsupported)
	}
	return nil
}

// ObjCSelectorBaseUnavailable reports whether ObjC parsing encountered a
// relative method list whose selectors are offsets into the shared cache's
// global selector-string table. That table is absent when a dylib is parsed in
// isolation (e.g. extracted from a dyld_shared_cache), so such method names
// cannot be resolved without the full cache. See [ErrObjCSelectorBaseUnavailable].
func (f *Reader) ObjCSelectorBaseUnavailable() bool {
	return f.objcSelectorBaseUnavailable
}
