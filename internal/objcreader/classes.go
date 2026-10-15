package objcreader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/blacktop/go-macho/types/objc"
)

// GetObjCClassInfo returns the ClassRO64 (class_ro_t) for a given virtual memory address
func (f *Reader) GetObjCClassInfo(vmaddr uint64) (*objc.ClassRO64, error) {
	var classData objc.ClassRO64
	if err := f.CheckFileData(vmaddr, uint64(binary.Size(classData))); err != nil {
		return nil, fmt.Errorf("failed to read class_ro_t: %w", err)
	}

	if err := f.DataReader().SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to vmaddr: %v", err)
	}

	if err := binary.Read(f.DataReader(), f.ByteOrder(), &classData); err != nil {
		return nil, fmt.Errorf("failed to read %T: %v", classData, err)
	}

	// slide pointers
	classData.NameVMAddr = f.ConvertPointer(classData.NameVMAddr)
	classData.IvarsVMAddr = f.ConvertPointer(classData.IvarsVMAddr)
	classData.IvarLayoutVMAddr = f.ConvertPointer(classData.IvarLayoutVMAddr)
	classData.BaseMethodsVMAddr = f.ConvertPointer(classData.BaseMethodsVMAddr)
	classData.BaseProtocolsVMAddr = f.ConvertPointer(classData.BaseProtocolsVMAddr)
	classData.WeakIvarLayoutVMAddr = f.ConvertPointer(classData.WeakIvarLayoutVMAddr)
	classData.BasePropertiesVMAddr = f.ConvertPointer(classData.BasePropertiesVMAddr)

	return &classData, nil
}

// GetObjCClasses returns an array of Objective-C classes
func (f *Reader) GetObjCClasses() ([]objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClasses"); err != nil {
		return nil, err
	}

	var classes []objc.Class

	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			if sec := f.Section(s, "__objc_classlist"); sec != nil { // An array of pointers to ObjC classes
				ptrs, err := f.readSectionPointers(sec)
				if err != nil {
					return nil, err
				}
				for _, ptr := range ptrs {
					addr := f.ConvertPointer(ptr)
					if c, ok := f.GetObjC(addr); ok {
						classes = append(classes, *c.(*objc.Class))
					} else {
						class, err := f.GetObjCClass2(addr)
						if err != nil {
							if f.HasFixups() {
								bindName, bindErr := f.GetBindName(ptr)
								if bindErr == nil {
									class = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
								} else {
									return nil, fmt.Errorf(
										"failed to read objc_class_t at vmaddr %#x: %w",
										ptr, errors.Join(err, bindErr))
								}
							} else {
								return nil, fmt.Errorf("failed to read objc_class_t at vmaddr %#x: %v", ptr, err)
							}
						}
						classes = append(classes, *class)
						if err == nil {
							f.PutObjC(addr, class)
						}
					}
				}
			}
		}
	}

	return f.appendObjCResilientClasses(classes)
}

// GetObjCNonLazyClasses returns an array of Objective-C classes that implement +load
func (f *Reader) GetObjCNonLazyClasses() ([]objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCNonLazyClasses"); err != nil {
		return nil, err
	}

	var classes []objc.Class

	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			// An array of pointers to classes who implement +load
			if sec := f.Section(s, "__objc_nlclslist"); sec != nil {
				ptrs, err := f.readSectionPointers(sec)
				if err != nil {
					return nil, err
				}
				for _, ptr := range ptrs {
					ptr = f.ConvertPointer(ptr)
					if c, ok := f.GetObjC(ptr); ok {
						classes = append(classes, *c.(*objc.Class))
					} else {
						class, err := f.GetObjCClass2(ptr)
						if err != nil {
							return nil, fmt.Errorf("failed to read non-lazy objc_class_t at vmaddr %#x: %v", ptr, err)
						}
						classes = append(classes, *class)
						f.PutObjC(ptr, class)
					}
				}
			}
		}
	}

	return classes, nil
}

func (f *Reader) disablePreattachedCategories(vmaddr uint64) (uint64, error) {
	if (vmaddr & 1) != 0 { // has preattached categories
		if err := f.DataReader().SeekToAddr(vmaddr & 0xFFFFFFFFFFFFFFFE); err != nil {
			return 0, fmt.Errorf("failed to seek to entry_list_t at %#x: %v", vmaddr&0xFFFFFFFFFFFFFFFE, err)
		}

		var entryList objc.EntryList
		if err := binary.Read(f.DataReader(), f.ByteOrder(), &entryList); err != nil {
			return 0, fmt.Errorf("failed to read entry_list_t at %#x: %v", vmaddr&0xFFFFFFFFFFFFFFFE, err)
		}

		entries := make([]objc.Entry, entryList.Count)
		if err := binary.Read(f.DataReader(), f.ByteOrder(), &entries); err != nil {
			return 0, fmt.Errorf("failed to read entries[entry_count]: %v", err)
		}

		curr := (vmaddr & 0xFFFFFFFFFFFFFFFE) + uint64(binary.Size(entryList))

		var mladdrs []uint64
		for idx, entry := range entries {
			mladdrs = append(mladdrs,
				uint64(int64(curr)+int64(idx*binary.Size(entry))+entry.MethodListOffset()))
		}

		return mladdrs[len(mladdrs)-1], nil
	}
	return vmaddr, nil
}

// GetObjCClass parses an Objective-C class at a given virtual memory address.
func (f *Reader) GetObjCClass(vmaddr uint64) (*objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClass"); err != nil {
		return nil, err
	}
	return f.readObjCClass(vmaddr, true)
}

// GetObjCClass2 preserves the raw method-cache bucket field.
func (f *Reader) GetObjCClass2(vmaddr uint64) (*objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClass2"); err != nil {
		return nil, err
	}
	return f.readObjCClass(vmaddr, false)
}

func (f *Reader) readObjCClass(vmaddr uint64, decodeBuckets bool) (*objc.Class, error) {
	if c, ok := f.GetObjC(vmaddr); ok {
		return c.(*objc.Class), nil
	}
	classPtr, err := f.readObjCClassRecord(vmaddr, decodeBuckets)
	if err != nil {
		return nil, err
	}
	info, err := f.GetObjCClassInfo(classPtr.DataVMAddrAndFastFlags & objc.FAST_DATA_MASK64)
	if err != nil {
		return nil, fmt.Errorf("failed to get class info at vmaddr: %#x; %v",
			classPtr.DataVMAddrAndFastFlags&objc.FAST_DATA_MASK64, err)
	}
	isSwiftClass := classPtr.DataVMAddrAndFastFlags&
		(objc.FAST_IS_SWIFT_LEGACY|objc.FAST_IS_SWIFT_STABLE) != 0
	class, err := f.readObjCClassRO(info, isSwiftClass)
	if err != nil {
		return nil, err
	}
	superClass, err := f.objcSuperclass(vmaddr, classPtr, info.Flags, decodeBuckets)
	if err != nil {
		return nil, err
	}
	isaClass, methods, err := f.objcIsa(vmaddr, classPtr, info.Flags)
	if err != nil {
		return nil, err
	}
	class.SuperClass, class.Isa, class.ClassMethods = superClass.Name, isaClass.Name, methods
	class.ClassPtr = vmaddr
	class.IsaVMAddr = classPtr.IsaVMAddr
	class.SuperclassVMAddr = classPtr.SuperclassVMAddr
	class.MethodCacheBuckets = classPtr.MethodCacheBuckets
	class.MethodCacheProperties = classPtr.MethodCacheProperties
	class.DataVMAddr = classPtr.DataVMAddrAndFastFlags & objc.FAST_DATA_MASK64
	class.IsSwiftLegacy = classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_LEGACY != 0
	class.IsSwiftStable = classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_STABLE != 0
	return class, nil
}

func (f *Reader) readObjCClassRecord(
	vmaddr uint64, decodeBuckets bool,
) (objc.ObjcClass64, error) {
	var classPtr objc.ObjcClass64
	if err := f.CheckFileData(vmaddr, uint64(binary.Size(classPtr))); err != nil {
		return classPtr, fmt.Errorf("failed to read objc_class_t: %w", err)
	}
	if err := f.DataReader().SeekToAddr(vmaddr); err != nil {
		return classPtr, fmt.Errorf("failed to seek to addr %#x: %v", vmaddr, err)
	}
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &classPtr); err != nil {
		return classPtr, fmt.Errorf("failed to read %T: %v", classPtr, err)
	}
	classPtr.IsaVMAddr = f.ConvertPointer(classPtr.IsaVMAddr)
	classPtr.SuperclassVMAddr = f.ConvertPointer(classPtr.SuperclassVMAddr)
	if decodeBuckets {
		classPtr.MethodCacheBuckets = f.ConvertPointer(classPtr.MethodCacheBuckets)
	}
	classPtr.MethodCacheProperties = f.ConvertPointer(classPtr.MethodCacheProperties)
	classPtr.DataVMAddrAndFastFlags = f.ConvertPointer(classPtr.DataVMAddrAndFastFlags)
	return classPtr, nil
}

func (f *Reader) objcSuperclass(
	vmaddr uint64, ptr objc.ObjcClass64, flags objc.ClassRoFlags, decodeBuckets bool,
) (*objc.Class, error) {
	if ptr.SuperclassVMAddr == 0 {
		return f.boundObjCClass(vmaddr+uint64(unsafe.Offsetof(ptr.SuperclassVMAddr)), flags), nil
	}
	if flags.IsRoot() {
		return &objc.Class{Name: "<ROOT>"}, nil
	}
	if flags.IsMeta() {
		return &objc.Class{Name: "<META>"}, nil
	}
	class, _, err := f.resolveObjCClass(ptr.SuperclassVMAddr, vmaddr, decodeBuckets)
	return class, err
}

func (f *Reader) objcIsa(
	vmaddr uint64, ptr objc.ObjcClass64, flags objc.ClassRoFlags,
) (*objc.Class, []objc.Method, error) {
	if ptr.IsaVMAddr == 0 {
		return f.boundObjCClass(vmaddr+uint64(unsafe.Offsetof(ptr.IsaVMAddr)), flags), nil, nil
	}
	if flags.IsMeta() {
		return &objc.Class{}, nil, nil
	}
	class, cached, err := f.resolveObjCClass(ptr.IsaVMAddr, vmaddr, true)
	if err != nil {
		return nil, nil, err
	}
	if cached || class.ReadOnlyData.Flags.IsMeta() {
		return class, class.InstanceMethods, nil
	}
	return class, nil, nil
}

// resolveObjCClass caches only successfully parsed class records.
func (f *Reader) resolveObjCClass(
	addr, owner uint64, decodeBuckets bool,
) (*objc.Class, bool, error) {
	if value, ok := f.GetObjC(addr); ok {
		return value.(*objc.Class), true, nil
	}
	class, err := f.readObjCClass(addr, decodeBuckets)
	if err == nil {
		f.PutObjC(addr, class)
		return class, false, nil
	}
	if !f.HasFixups() {
		return &objc.Class{}, false, nil
	}
	name, bindErr := f.GetBindName(addr)
	if bindErr != nil {
		return nil, false, fmt.Errorf(
			"failed to read objc_class_t at vmaddr: %#x referenced by class %#x; %w",
			addr, owner, errors.Join(err, bindErr))
	}
	return &objc.Class{Name: strings.TrimPrefix(name, "_OBJC_CLASS_$_")}, false, nil
}

func (f *Reader) boundObjCClass(slot uint64, flags objc.ClassRoFlags) *objc.Class {
	name, err := f.GetBindName(slot)
	if err != nil {
		return &objc.Class{}
	}
	if flags.IsRoot() {
		return &objc.Class{Name: name}
	}
	if flags.IsMeta() {
		name = strings.TrimPrefix(name, "_OBJC_METACLASS_$_")
	} else {
		name = strings.TrimPrefix(name, "_OBJC_CLASS_$_")
	}
	return &objc.Class{Name: name}
}

// readObjCClassRO decodes the data shared by static classes and Swift resilient
// class metadata patterns. It does not require a realized class object.
func (f *Reader) readObjCClassRO(info *objc.ClassRO64, isSwiftClass bool) (*objc.Class, error) {
	name, err := f.GetCString(info.NameVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	var methods []objc.Method
	if info.BaseMethodsVMAddr > 0 {
		info.BaseMethodsVMAddr, err = f.disablePreattachedCategories(info.BaseMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		methods, err = f.GetObjCMethods(info.BaseMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get methods at vmaddr: %#x; %v", info.BaseMethodsVMAddr, err)
		}
	}

	var prots []objc.Protocol
	if info.BaseProtocolsVMAddr > 0 {
		info.BaseProtocolsVMAddr, err = f.disablePreattachedCategories(info.BaseProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		prots, err = f.parseObjcProtocolList(info.BaseProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}

	var ivars []objc.Ivar
	if info.IvarsVMAddr > 0 {
		ivars, err = f.getObjCIvarsWithSwift(info.IvarsVMAddr, isSwiftClass)
		if err != nil {
			return nil, fmt.Errorf("failed to get ivars at vmaddr: %#x; %v", info.IvarsVMAddr, err)
		}
		if isSwiftClass {
			if fieldMap, ferr := f.SwiftFieldTypesForClass(name); ferr == nil && len(fieldMap) > 0 {
				for idx := range ivars {
					if typ, ok := matchSwiftFieldType(ivars[idx].Name, fieldMap); ok {
						ivars[idx].Type = typ
					}
				}
			}
		}
	}

	var props []objc.Property
	if info.BasePropertiesVMAddr > 0 {
		info.BasePropertiesVMAddr, err = f.disablePreattachedCategories(info.BasePropertiesVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		props, err = f.getObjCPropertiesWithSwift(info.BasePropertiesVMAddr, isSwiftClass)
		if err != nil {
			return nil, fmt.Errorf("failed to get props at vmaddr: %#x; %v", info.BasePropertiesVMAddr, err)
		}
	}

	return &objc.Class{
		Name: name, InstanceMethods: methods, Protocols: prots,
		Ivars: ivars, Props: props, ReadOnlyData: *info,
	}, nil
}
