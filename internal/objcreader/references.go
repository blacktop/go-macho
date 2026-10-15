package objcreader

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types/objc"
)

// GetObjCClassReferences returns a map of classes to their section data virtual memory address
func (f *Reader) GetObjCClassReferences() (map[uint64]*objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClassReferences"); err != nil {
		return nil, err
	}

	clsRefs := make(map[uint64]*objc.Class)

	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			if sec := f.Section(s, "__objc_classrefs"); sec != nil { // External references to other classes
				classPtrs, err := f.readSectionPointers(sec)
				if err != nil {
					return nil, err
				}
				for idx, ptr := range classPtrs {
					ptr = f.ConvertPointer(ptr)
					if c, ok := f.GetObjC(ptr); ok {
						clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = c.(*objc.Class)
					} else {
						if cls, err := f.GetObjCClass(ptr); err != nil {
							if f.HasFixups() {
								if bindName, bindErr := f.GetBindName(ptr); bindErr == nil {
									clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = &objc.Class{
										Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_"),
									}
								} else {
									return nil, fmt.Errorf(
										"failed to read objc_class_t at classref ptr: %#x; %w",
										ptr, errors.Join(err, bindErr))
								}
							}
						} else {
							clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = cls
							f.PutObjC(ptr, cls)
						}
					}
				}
			}
		}
	}

	return clsRefs, nil
}

// GetObjCSuperReferences returns a map of super classes to their section data virtual memory
// address
func (f *Reader) GetObjCSuperReferences() (map[uint64]*objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCSuperReferences"); err != nil {
		return nil, err
	}

	clsRefs := make(map[uint64]*objc.Class)

	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			if sec := f.Section(s, "__objc_superrefs"); sec != nil { // External references to super classes
				classPtrs, err := f.readSectionPointers(sec)
				if err != nil {
					return nil, err
				}
				for idx, ptr := range classPtrs {
					ptr = f.ConvertPointer(ptr)
					if c, ok := f.GetObjC(ptr); ok {
						clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = c.(*objc.Class)
					} else {
						if cls, err := f.GetObjCClass(ptr); err != nil {
							if f.HasFixups() {
								if bindName, bindErr := f.GetBindName(ptr); bindErr == nil {
									clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = &objc.Class{
										Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_"),
									}
								} else {
									return nil, fmt.Errorf(
										"failed to read objc_class_t at superref ptr: %#x; %w",
										ptr, errors.Join(err, bindErr))
								}
							}
						} else {
							clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = cls
							f.PutObjC(ptr, cls)
						}
					}
				}
			}
		}
	}
	return clsRefs, nil
}

// GetObjCProtoReferences maps each protocol-reference slot to its protocol.
// It returns an error if a referenced protocol is unavailable or truncated.
func (f *Reader) GetObjCProtoReferences() (map[uint64]*objc.Protocol, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCProtoReferences"); err != nil {
		return nil, err
	}

	protRefs := make(map[uint64]*objc.Protocol)

	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			// External references to protocols and list of ObjC protocols
			for _, secName := range []string{"__objc_protorefs", "__objc_protolist"} {
				if sec := f.Section(s, secName); sec != nil {
					protoPtrs, err := f.readSectionPointers(sec)
					if err != nil {
						return nil, err
					}
					for idx, ptr := range protoPtrs {
						addr := f.ConvertPointer(ptr)
						proto, err := f.getObjcProtocol(addr)
						if err != nil {
							return nil, fmt.Errorf(
								"failed to read protocol_t at ptr: %#x (converted %#x); %w",
								ptr, addr, err)
						}
						if proto == nil {
							return nil, fmt.Errorf("protocol reference at %#x is unavailable", addr)
						}
						protRefs[sec.Addr+uint64(idx*sizeOfInt64)] = proto
					}
				}
			}
		}
	}

	return protRefs, nil
}

// GetObjCSelectorReferences returns a map of selector names to their section data virtual
// memory address
func (f *Reader) GetObjCSelectorReferences() (map[uint64]*objc.Selector, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCSelectorReferences"); err != nil {
		return nil, err
	}

	selRefs := make(map[uint64]*objc.Selector)

	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			if sec := f.Section(s, "__objc_selrefs"); sec != nil { // External references to selectors
				selPtrs, err := f.readSectionPointers(sec)
				if err != nil {
					return nil, err
				}
				for idx, sel := range selPtrs {
					sel = f.ConvertPointer(sel)
					selName, err := f.GetCString(sel)
					if err != nil {
						return nil, fmt.Errorf("failed to read selector name cstring: %v", err)
					}
					selRefs[sec.Addr+uint64(idx*sizeOfInt64)] = &objc.Selector{
						VMAddr: sel,
						Name:   selName,
					}
				}
			}
		}
	}

	return selRefs, nil
}
