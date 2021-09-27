package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

// TODO refactor into a pkg
func (f *File) HasObjC() bool {
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_imageinfo"); sec != nil {
				return true
			}
		}
	}
	if f.CPU == types.CPU386 {
		if sec := f.Section("__OBJC", "__image_info"); sec != nil {
			return true
		}
	}
	return false
}

func (f *File) HasPlusLoadMethod() bool {
	// TODO add the old way of detecting from dyld3/MachOAnalyzer.cpp
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_nlclslist"); sec != nil {
				return true
			}
			if sec := f.Section(s.Name, "__objc_nlcatlist"); sec != nil {
				return true
			}
		}
	}
	return false
}

func (f *File) HasObjCMessageReferences() bool {
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			for j := uint32(0); j < s.Nsect; j++ {
				c := f.FileTOC.Sections[j+s.Firstsect]
				if strings.EqualFold("__objc_msgrefs", c.Name) {
					return true
				}
			}
		}
	}
	return false
}

func (f *File) GetObjCInfo() objc.Info {
	var oInfo objc.Info

	for _, sec := range f.FileTOC.Sections {
		if strings.HasPrefix(sec.SectionHeader.Seg, "__DATA") {
			if strings.EqualFold(sec.Name, "__objc_selrefs") {
				oInfo.SelRefCount += sec.SectionHeader.Size / f.pointerSize()
			} else if strings.EqualFold(sec.Name, "__objc_classlist") {
				oInfo.ClassDefCount += sec.SectionHeader.Size / f.pointerSize()
			} else if strings.EqualFold(sec.Name, "__objc_protolist") {
				oInfo.ProtocolDefCount += sec.SectionHeader.Size / f.pointerSize()
			}
		} else if (f.CPU == types.CPU386) && strings.EqualFold(sec.Name, "__OBJC") {
			if strings.EqualFold(sec.Name, "__message_refs") {
				oInfo.SelRefCount += sec.SectionHeader.Size / 4
			} else if strings.EqualFold(sec.Name, "__class") {
				oInfo.ClassDefCount += sec.SectionHeader.Size / 48
			} else if strings.EqualFold(sec.Name, "__protocol") {
				oInfo.ProtocolDefCount += sec.SectionHeader.Size / 20
			}
		}
	}
	return oInfo
}

func (f *File) GetObjCImageInfo() (*objc.ImageInfo, error) {
	var imgInfo objc.ImageInfo
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_imageinfo"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_imageinfo: %v", err)
				}

				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &imgInfo); err != nil {
					return nil, fmt.Errorf("failed to read ObjCImageInfo: %v", err)
				}

				return &imgInfo, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain a __objc_imageinfo section")
}

func (f *File) GetObjCClassInfo(vmaddr uint64) (*objc.ClassRO64, error) {
	var classData objc.ClassRO64

	if f.Flags.DylibInCache() {
		f.cr.SeekToAddr(vmaddr)
	} else {
		off, err := f.GetOffset(vmaddr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &classData); err != nil {
		return nil, fmt.Errorf("failed to read class_ro_t: %v", err)
	}

	return &classData, nil
}

func (f *File) GetObjCMethodNames() (map[string]uint64, error) {
	meth2vmaddr := make(map[string]uint64)

	if sec := f.Section("__TEXT", "__objc_methname"); sec != nil {
		if sec.Size == 0 {
			return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
		}

		off, err := f.vma.GetOffset(sec.Addr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}

		stringPool := make([]byte, sec.Size)

		if _, err := f.cr.ReadAt(stringPool, int64(off)); err != nil {
			return nil, err
		}

		r := bytes.NewBuffer(stringPool[:])

		for {
			s, err := r.ReadString('\x00')
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read from method name string pool: %v", err)
			}
			meth2vmaddr[strings.Trim(s, "\x00")] = sec.Addr + (sec.Size - uint64(r.Len()+len(s)))
		}
		return meth2vmaddr, nil
	}

	return nil, fmt.Errorf("macho does not contain a __TEXT.__objc_methname section")
}

func (f *File) GetObjCClasses() ([]objc.Class, error) {
	var classes []objc.Class

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_classlist"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_classlist: %v", err)
				}

				ptrs := make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &ptrs); err != nil {
					return nil, fmt.Errorf("failed to read objc_class_t pointers: %v", err)
				}

				for _, ptr := range ptrs {
					class, err := f.GetObjCClass(f.vma.Convert(ptr))
					if err != nil {
						return nil, fmt.Errorf("failed to read objc_class_t at vmaddr: %#x (converted %#x); %v", ptr, f.vma.Convert(ptr), err)
					}
					classes = append(classes, *class)
				}
				return classes, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain a __objc_classlist section")
}

func (f *File) GetObjCPlusLoadClasses() ([]objc.Class, error) {
	var classes []objc.Class

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_nlclslist"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_nlclslist: %v", err)
				}

				ptrs := make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &ptrs); err != nil {
					return nil, fmt.Errorf("failed to read objc_class_t pointers: %v", err)
				}

				for _, ptr := range ptrs {
					class, err := f.GetObjCClass(f.vma.Convert(ptr))
					if err != nil {
						return nil, fmt.Errorf("failed to read objc_class_t at vmaddr: %#x; %v", ptr, err)
					}
					classes = append(classes, *class)
				}
				return classes, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain a __objc_nlclslist section")
}

// GetObjCClass parses an ObjC class at a given virtual memory address
func (f *File) GetObjCClass(vmaddr uint64) (*objc.Class, error) {
	var classPtr objc.SwiftClassMetadata64

	if f.Flags.DylibInCache() {
		f.cr.SeekToAddr(vmaddr)
	} else {
		off, err := f.vma.GetOffset(vmaddr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &classPtr); err != nil {
		return nil, fmt.Errorf("failed to read swift_class_metadata_t: %v", err)
	}

	info, err := f.GetObjCClassInfo(f.vma.Convert(classPtr.DataVMAddrAndFastFlags) & objc.FAST_DATA_MASK64)
	if err != nil {
		return nil, fmt.Errorf("failed to get class info at vmaddr: %#x; %v", classPtr.DataVMAddrAndFastFlags&objc.FAST_DATA_MASK64, err)
	}

	name, err := f.GetCString(f.vma.Convert(info.NameVMAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	var methods []objc.Method
	if info.BaseMethodsVMAddr > 0 {
		methods, err = f.GetObjCMethods(f.vma.Convert(info.BaseMethodsVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to get methods at vmaddr: %#x; %v", info.BaseMethodsVMAddr, err)
		}
	}

	var prots []objc.Protocol
	if info.BaseProtocolsVMAddr > 0 {
		prots, err = f.parseObjcProtocolList(f.vma.Convert(info.BaseProtocolsVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}

	var ivars []objc.Ivar
	if info.IvarsVMAddr > 0 {
		ivars, err = f.GetObjCIvars(f.vma.Convert(info.IvarsVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to get ivars at vmaddr: %#x; %v", info.IvarsVMAddr, err)
		}
	}

	var props []objc.Property
	if info.BasePropertiesVMAddr > 0 {
		props, err = f.GetObjCProperties(f.vma.Convert(info.BasePropertiesVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to get props at vmaddr: %#x; %v", info.BasePropertiesVMAddr, err)
		}
	}

	superClass := &objc.Class{Name: "<ROOT>"}
	if classPtr.SuperclassVMAddr > 0 {
		if !info.Flags.IsRoot() {
			superClass, err = f.GetObjCClass(f.vma.Convert(classPtr.SuperclassVMAddr))
			if err != nil {
				if f.HasFixups() {
					bindName, err := f.GetBindName(classPtr.SuperclassVMAddr)
					if err == nil {
						superClass = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
					} else {
						return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %v", vmaddr, err)
					}
				}
			}
		}
	}

	isaClass := &objc.Class{}
	var cMethods []objc.Method
	if classPtr.IsaVMAddr > 0 {
		if !info.Flags.IsMeta() {
			isaClass, err = f.GetObjCClass(f.vma.Convert(classPtr.IsaVMAddr))
			if err != nil {
				bindName, err := f.GetBindName(classPtr.IsaVMAddr)
				if err == nil {
					isaClass = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
				} else {
					return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %v", vmaddr, err)
				}
			} else {
				if isaClass.ReadOnlyData.Flags.IsMeta() {
					cMethods = isaClass.InstanceMethods
				}
			}
		}
	}

	return &objc.Class{
		Name:                  name,
		SuperClass:            superClass.Name,
		Isa:                   isaClass.Name,
		InstanceMethods:       methods,
		ClassMethods:          cMethods,
		Ivars:                 ivars,
		Props:                 props,
		Prots:                 prots,
		ClassPtr:              vmaddr,
		IsaVMAddr:             f.vma.Convert(classPtr.IsaVMAddr),
		SuperclassVMAddr:      f.vma.Convert(classPtr.SuperclassVMAddr),
		MethodCacheBuckets:    classPtr.MethodCacheBuckets,
		MethodCacheProperties: classPtr.MethodCacheProperties,
		DataVMAddr:            f.vma.Convert(classPtr.DataVMAddrAndFastFlags) & objc.FAST_DATA_MASK64,
		IsSwiftLegacy:         (classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_LEGACY == 1),
		IsSwiftStable:         (classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_STABLE == 1),
		ReadOnlyData:          *info,
	}, nil
}

func (f *File) GetObjCCategories() ([]objc.Category, error) {
	var categoryPtr objc.CategoryT
	var categories []objc.Category

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_catlist"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_catlist: %v", err)
				}
				ptrs := make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &ptrs); err != nil {
					return nil, fmt.Errorf("failed to read objc_category_t pointers: %v", err)
				}

				for _, ptr := range ptrs {
					if f.Flags.DylibInCache() {
						f.cr.SeekToAddr(f.vma.Convert(ptr))
					} else {
						off, err := f.vma.GetOffset(f.vma.Convert(ptr))
						if err != nil {
							return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
						}
						f.cr.Seek(int64(off), io.SeekStart)
					}

					if err := binary.Read(f.cr, f.ByteOrder, &categoryPtr); err != nil {
						return nil, fmt.Errorf("failed to read objc_category_t: %v", err)
					}

					category := objc.Category{VMAddr: ptr, CategoryT: categoryPtr}

					category.Name, err = f.GetCString(f.vma.Convert(categoryPtr.NameVMAddr))
					if err != nil {
						return nil, fmt.Errorf("failed to read cstring: %v", err)
					}

					if categoryPtr.ClassMethodsVMAddr > 0 {
						category.ClassMethods, err = f.GetObjCMethods(f.vma.Convert(categoryPtr.ClassMethodsVMAddr))
						if err != nil {
							return nil, fmt.Errorf("failed to get class methods at vmaddr: %#x; %v", categoryPtr.ClassMethodsVMAddr, err)
						}
					}

					if categoryPtr.InstanceMethodsVMAddr > 0 {
						category.InstanceMethods, err = f.GetObjCMethods(f.vma.Convert(categoryPtr.InstanceMethodsVMAddr))
						if err != nil {
							return nil, fmt.Errorf("failed to get instance methods at vmaddr: %#x; %v", categoryPtr.InstanceMethodsVMAddr, err)
						}
					}

					categories = append(categories, category)
				}

				return categories, nil
			}
		}
	}

	return nil, fmt.Errorf("macho does not contain a __objc_catlist section")
}

// GetCFStrings parses all the cfstrings in tne MachO
func (f *File) GetCFStrings() ([]objc.CFString, error) {

	var cfstrings []objc.CFString

	for _, s := range f.Segments() {
		if sec := f.Section(s.Name, "__cfstring"); sec != nil {
			if sec.Size == 0 {
				return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
			}

			dat, err := sec.Data()
			if err != nil {
				return nil, fmt.Errorf("failed to read __cfstring: %v", err)
			}

			cfstrings = make([]objc.CFString, int(sec.Size)/binary.Size(objc.CFString64T{}))
			cfStrTypes := make([]objc.CFString64T, int(sec.Size)/binary.Size(objc.CFString64T{}))
			if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &cfStrTypes); err != nil {
				return nil, fmt.Errorf("failed to read cfstring64_t structs: %v", err)
			}

			for idx, cfstr := range cfStrTypes {
				cfstrings[idx].CFString64T = &cfstr
				if cfstr.Data == 0 {
					return nil, fmt.Errorf("unhandled cstring parse case where data is 0")
					// uint64_t n_value;
					// const char *symbol_name = get_symbol_64(offset + offsetof(struct cfstring64_t, characters), S, info, n_value);
					// if (symbol_name == nullptr)
					//   return nullptr;
					// cfs_characters = n_value;
				}
				cfstrings[idx].Name, err = f.GetCString(f.vma.Convert(cfstr.Data))
				if err != nil {
					return nil, fmt.Errorf("failed to read cstring: %v", err)
				}
				cfstrings[idx].Address = sec.Addr + uint64(idx*binary.Size(objc.CFString64T{}))
				if err != nil {
					return nil, fmt.Errorf("failed to calulate cfstring vmaddr: %v", err)
				}
			}

			return cfstrings, nil
		}
	}

	return nil, fmt.Errorf("macho does not contain a __DATA.__cfstring section")
}

func (f *File) parseObjcProtocolList(vmaddr uint64) ([]objc.Protocol, error) {
	var protocols []objc.Protocol

	if f.Flags.DylibInCache() {
		f.cr.SeekToAddr(vmaddr)
	} else {
		off, err := f.vma.GetOffset(f.vma.Convert(vmaddr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)
	}

	var protList objc.ProtocolList
	if err := binary.Read(f.cr, f.ByteOrder, &protList.Count); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t count: %v", err)
	}

	protList.Protocols = make([]uint64, protList.Count)
	if err := binary.Read(f.cr, f.ByteOrder, &protList.Protocols); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t prots: %v", err)
	}

	for _, protPtr := range protList.Protocols {
		prot, err := f.getObjcProtocol(f.vma.Convert(protPtr))
		if err != nil {
			return nil, err
		}
		protocols = append(protocols, *prot)
	}

	return protocols, nil
}

func (f *File) getObjcProtocol(vmaddr uint64) (proto *objc.Protocol, err error) {
	var protoPtr objc.ProtocolT

	if f.Flags.DylibInCache() {
		f.cr.SeekToAddr(f.vma.Convert(vmaddr))
	} else {
		off, err := f.vma.GetOffset(f.vma.Convert(vmaddr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &protoPtr); err != nil {
		return nil, fmt.Errorf("failed to read protocol_t: %v", err)
	}

	proto = &objc.Protocol{
		Ptr:       vmaddr,
		ProtocolT: protoPtr,
	}

	if protoPtr.NameVMAddr > 0 {
		proto.Name, err = f.GetCString(f.vma.Convert(protoPtr.NameVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	}
	// if protoPtr.IsaVMAddr > 0 {
	// 	isa, err := f.getObjcProtocol(f.vma.Convert(protoPtr.IsaVMAddr))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if len(isa.DemangledName) > 0 {
	// 		proto.Isa = isa.DemangledName
	// 	} else {
	// 		proto.Isa = isa.Name
	// 	}
	// }
	if protoPtr.ProtocolsVMAddr > 0 {
		proto.Prots, err = f.parseObjcProtocolList(f.vma.Convert(protoPtr.ProtocolsVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}
	if protoPtr.InstanceMethodsVMAddr > 0 {
		proto.InstanceMethods, err = f.GetObjCMethods(f.vma.Convert(protoPtr.InstanceMethodsVMAddr))
		if err != nil {
			return nil, err
		}
	}
	if protoPtr.OptionalInstanceMethodsVMAddr > 0 {
		proto.OptionalInstanceMethods, err = f.GetObjCMethods(f.vma.Convert(protoPtr.OptionalInstanceMethodsVMAddr))
		if err != nil {
			return nil, err
		}
	}
	if protoPtr.ClassMethodsVMAddr > 0 {
		proto.ClassMethods, err = f.GetObjCMethods(f.vma.Convert(protoPtr.ClassMethodsVMAddr))
		if err != nil {
			return nil, err
		}
	}
	if protoPtr.OptionalClassMethodsVMAddr > 0 {
		proto.OptionalClassMethods, err = f.GetObjCMethods(f.vma.Convert(protoPtr.OptionalClassMethodsVMAddr))
		if err != nil {
			return nil, err
		}
	}
	if protoPtr.InstancePropertiesVMAddr > 0 {
		proto.InstanceProperties, err = f.GetObjCProperties(f.vma.Convert(protoPtr.InstancePropertiesVMAddr))
		if err != nil {
			return nil, err
		}
	}
	if protoPtr.ExtendedMethodTypesVMAddr > 0 {

		if f.Flags.DylibInCache() {
			f.cr.SeekToAddr(f.vma.Convert(protoPtr.ExtendedMethodTypesVMAddr))
		} else {
			off, err := f.vma.GetOffset(f.vma.Convert(protoPtr.ExtendedMethodTypesVMAddr))
			if err != nil {
				return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
			}
			f.cr.Seek(int64(off), io.SeekStart)
		}

		var extMPtr uint64
		if err := binary.Read(f.cr, f.ByteOrder, &extMPtr); err != nil {
			return nil, fmt.Errorf("failed to read ExtendedMethodTypesVMAddr: %v", err)
		}

		proto.ExtendedMethodTypes, err = f.GetCString(f.vma.Convert(extMPtr))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	}
	if protoPtr.DemangledNameVMAddr > 0 {
		dnOff, err := f.vma.GetOffset(f.vma.Convert(protoPtr.DemangledNameVMAddr)) // TODO: make sure this works
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}

		// f.cr.Seek(int64(dnOff), io.SeekStart)
		// var dnPtr int64
		// if err := binary.Read(f.cr, f.ByteOrder, &dnPtr); err != nil {
		// 	return nil, fmt.Errorf("failed to read DemangledNameVMAddr: %v", err)
		// }

		proto.DemangledName, err = f.GetCStringAtOffset(int64(dnOff))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	}

	return proto, nil
}

func (f *File) GetObjCProtocols() ([]objc.Protocol, error) {

	var protocols []objc.Protocol

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_protolist"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_protolist: %v", err)
				}

				ptrs := make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &ptrs); err != nil {
					return nil, fmt.Errorf("failed to read protocol_t pointers: %v", err)
				}

				for _, ptr := range ptrs {
					proto, err := f.getObjcProtocol(f.vma.Convert(ptr))
					if err != nil {
						return nil, fmt.Errorf("failed to read protocol at pointer %#x: %v", ptr, err)
					}
					protocols = append(protocols, *proto)
				}
				return protocols, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain a __objc_protolist section")
}

func (f *File) GetObjCMethodList() ([]objc.Method, error) {
	var methodList objc.MethodList
	var objcMethods []objc.Method

	if sec := f.Section("__TEXT", "__objc_methlist"); sec != nil {
		if sec.Size == 0 {
			return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
		}

		mlr := io.NewSectionReader(f.cr, int64(sec.Offset), int64(sec.Size))

		for {
			err := binary.Read(mlr, f.ByteOrder, &methodList)

			currOffset, _ := mlr.Seek(0, io.SeekCurrent)
			currOffset += int64(sec.Offset)
			// currOffset += int64(sec.Offset) + int64(binary.Size(objc.MethodList{}))

			if err == io.EOF {
				break
			}

			if err != nil {
				return nil, fmt.Errorf("failed to read method_list_t: %v", err)
			}

			methods := make([]objc.MethodSmallT, methodList.Count)
			if err := binary.Read(mlr, f.ByteOrder, &methods); err != nil {
				return nil, fmt.Errorf("failed to read method_t(s) (small): %v", err)
			}

			for _, method := range methods {
				var nameAddr uint32
				f.cr.Seek(int64(method.NameOffset)+currOffset, io.SeekStart)
				if err := binary.Read(f.cr, f.ByteOrder, &nameAddr); err != nil {
					return nil, fmt.Errorf("failed to read nameAddr(small): %v", err)
				}
				n, err := f.GetCString(uint64(nameAddr))
				if err != nil {
					return nil, fmt.Errorf("failed to read cstring: %v", err)
				}

				typesVMAddr, err := f.vma.GetVMAddress(uint64(method.TypesOffset) + uint64(currOffset+4))
				if err != nil {
					return nil, fmt.Errorf("failed to convert offset %#x to vmaddr; %v", method.TypesOffset, err)
				}
				t, err := f.GetCString(f.vma.Convert(typesVMAddr))
				if err != nil {
					return nil, fmt.Errorf("failed to read cstring: %v", err)
				}

				impVMAddr, err := f.vma.GetVMAddress(uint64(method.ImpOffset) + uint64(currOffset+8))
				if err != nil {
					return nil, fmt.Errorf("failed to convert offset %#x to vmaddr; %v", method.ImpOffset, err)
				}

				currOffset += int64(methodList.EntSize())

				objcMethods = append(objcMethods, objc.Method{
					NameVMAddr:  uint64(nameAddr),
					TypesVMAddr: typesVMAddr,
					ImpVMAddr:   impVMAddr,
					Name:        n,
					Types:       t,
				})
			}

			curr, _ := mlr.Seek(0, io.SeekCurrent)
			align := types.RoundUp(uint64(curr), 8)
			mlr.Seek(int64(align), io.SeekStart)
		}

		return objcMethods, nil
	}
	return nil, fmt.Errorf("macho does not contain a __objc_methlist section")
}

func (f *File) GetObjCMethods(vmaddr uint64) ([]objc.Method, error) {

	var methodList objc.MethodList

	if f.Flags.DylibInCache() {
		f.cr.SeekToAddr(vmaddr)
	} else {
		off, err := f.vma.GetOffset(f.vma.Convert(vmaddr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &methodList); err != nil {
		return nil, fmt.Errorf("failed to read method_list_t: %v", err)
	}

	if methodList.IsSmall() {
		return f.readSmallMethods(methodList)
	}

	return f.readBigMethods(methodList)
}

func (f *File) readSmallMethods(methodList objc.MethodList) (objcMethods []objc.Method, err error) {

	var nameVMAddr uint64

	currOffset, _ := f.cr.Seek(0, io.SeekCurrent)

	methods := make([]objc.MethodSmallT, methodList.Count)
	if err := binary.Read(f.cr, f.ByteOrder, &methods); err != nil {
		return nil, fmt.Errorf("failed to read method_t(s) (small): %v", err)
	}

	for _, method := range methods {
		f.cr.Seek(currOffset+int64(method.NameOffset), io.SeekStart)
		if err := binary.Read(f.cr, f.ByteOrder, &nameVMAddr); err != nil {
			return nil, fmt.Errorf("failed to read nameAddr(small): %v", err)
		}

		if f.Flags.DylibInCache() {
			nameVMAddr, err = f.vma.GetVMAddress(uint64(currOffset + int64(method.NameOffset)))
			if err != nil {
				return nil, fmt.Errorf("failed to convert offset %#x to vmaddr; %v", currOffset+int64(method.NameOffset), err)
			}
			if f.relativeSelectorBase > 0 {
				nameVMAddr = f.relativeSelectorBase + uint64(method.NameOffset)
			}
		}

		n, err := f.GetCString(f.vma.Convert(nameVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}

		typesVMAddr, err := f.vma.GetVMAddress(uint64(currOffset + 4 + int64(method.TypesOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to convert offset %#x to vmaddr; %v", currOffset+4+int64(method.TypesOffset), err)
		}
		t, err := f.GetCString(f.vma.Convert(typesVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}

		impVMAddr, err := f.vma.GetVMAddress(uint64(currOffset + 8 + int64(method.ImpOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to convert offset %#x to vmaddr; %v", currOffset+8+int64(method.ImpOffset), err)
		}

		currOffset += int64(methodList.EntSize())

		objcMethods = append(objcMethods, objc.Method{
			NameVMAddr:  nameVMAddr,
			TypesVMAddr: typesVMAddr,
			ImpVMAddr:   impVMAddr,
			Name:        n,
			Types:       t,
		})
	}

	return objcMethods, nil
}

func (f *File) readBigMethods(methodList objc.MethodList) ([]objc.Method, error) {
	var objcMethods []objc.Method

	methods := make([]objc.MethodT, methodList.Count)
	if err := binary.Read(f.cr, f.ByteOrder, &methods); err != nil {
		return nil, fmt.Errorf("failed to read method_t: %v", err)
	}

	for _, method := range methods {
		n, err := f.GetCString(f.vma.Convert(uint64(method.NameVMAddr)))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
		t, err := f.GetCString(f.vma.Convert(uint64(method.TypesVMAddr)))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
		if method.ImpVMAddr > 0 {
			_, err := f.vma.GetOffset(f.vma.Convert(method.ImpVMAddr))
			if err != nil {
				return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
			}
		}
		objcMethods = append(objcMethods, objc.Method{
			NameVMAddr:  method.NameVMAddr,
			TypesVMAddr: method.TypesVMAddr,
			ImpVMAddr:   method.ImpVMAddr,
			Name:        n,
			Types:       t,
		})
	}

	return objcMethods, nil
}

func (f *File) GetObjCIvars(vmaddr uint64) ([]objc.Ivar, error) {

	var ivarsList objc.IvarList
	var ivars []objc.Ivar

	if f.Flags.DylibInCache() {
		f.cr.SeekToAddr(vmaddr)
	} else {
		off, err := f.vma.GetOffset(f.vma.Convert(vmaddr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &ivarsList); err != nil {
		return nil, fmt.Errorf("failed to read objc_ivar_list_t: %v", err)
	}

	ivs := make([]objc.IvarT, ivarsList.Count)
	if err := binary.Read(f.cr, f.ByteOrder, &ivs); err != nil {
		return nil, fmt.Errorf("failed to read objc_ivar_list_t: %v", err)
	}

	for _, ivar := range ivs {
		if f.Flags.DylibInCache() {
			f.cr.SeekToAddr(f.vma.Convert(uint64(ivar.Offset)))
		} else {
			off, err := f.GetOffset(f.vma.Convert(uint64(ivar.Offset)))
			if err != nil {
				return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
			}
			f.cr.Seek(int64(off), io.SeekStart)
		}

		var o uint32
		if err := binary.Read(f.cr, f.ByteOrder, &o); err != nil {
			return nil, fmt.Errorf("failed to read ivar.offset: %v", err)
		}
		n, err := f.GetCString(f.vma.Convert(uint64(ivar.NameVMAddr)))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
		t, err := f.GetCString(f.vma.Convert(uint64(ivar.TypesVMAddr)))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
		ivars = append(ivars, objc.Ivar{
			Name:   n,
			Type:   t,
			Offset: o,
			IvarT:  ivar,
		})
	}

	return ivars, nil
}

func (f *File) GetObjCProperties(vmaddr uint64) ([]objc.Property, error) {

	var propList objc.PropertyList
	var objcProperties []objc.Property

	if f.Flags.DylibInCache() {
		f.cr.SeekToAddr(vmaddr)
	} else {
		off, err := f.vma.GetOffset(f.vma.Convert(vmaddr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &propList); err != nil {
		return nil, fmt.Errorf("failed to read objc_property_list_t: %v", err)
	}

	properties := make([]objc.PropertyT, propList.Count)
	if err := binary.Read(f.cr, f.ByteOrder, &properties); err != nil {
		return nil, fmt.Errorf("failed to read objc_property_t: %v", err)
	}

	for _, prop := range properties {
		name, err := f.GetCString(f.vma.Convert(prop.NameVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
		attrib, err := f.GetCString(f.vma.Convert(prop.AttributesVMAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
		objcProperties = append(objcProperties, objc.Property{
			PropertyT:  prop,
			Name:       name,
			Attributes: attrib,
		})
	}

	return objcProperties, nil
}

func (f *File) GetObjCClassReferences() (map[uint64]*objc.Class, error) {
	var classPtrs []uint64
	clsRefs := make(map[uint64]*objc.Class)

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_classrefs"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_classrefs: %v", err)
				}

				classPtrs = make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &classPtrs); err != nil {
					return nil, fmt.Errorf("failed to read class ref pointers: %v", err)
				}

				for idx, ptr := range classPtrs {
					if cls, err := f.GetObjCClass(f.vma.Convert(ptr)); err != nil {
						if bindName, err := f.GetBindName(ptr); err == nil {
							clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
						} else {
							return nil, fmt.Errorf("failed to read objc_class_t at classref ptr: %#x; %v", ptr, err)
						}
					} else {
						clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = cls
					}
				}
				return clsRefs, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain a __objc_classrefs section")
}

func (f *File) GetObjCSuperReferences() (map[uint64]*objc.Class, error) {
	var classPtrs []uint64
	clsRefs := make(map[uint64]*objc.Class)

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_superrefs"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_superrefs: %v", err)
				}

				classPtrs = make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &classPtrs); err != nil {
					return nil, fmt.Errorf("failed to read super ref pointers: %v", err)
				}

				for idx, ptr := range classPtrs {
					if cls, err := f.GetObjCClass(f.vma.Convert(ptr)); err != nil {
						if bindName, err := f.GetBindName(ptr); err == nil {
							clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
						} else {
							return nil, fmt.Errorf("failed to read objc_class_t at superref ptr: %#x; %v", ptr, err)
						}
					} else {
						clsRefs[sec.Addr+uint64(idx*sizeOfInt64)] = cls
					}
				}
				return clsRefs, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain a __objc_superrefs section")
}

func (f *File) GetObjCProtoReferences() (map[uint64]*objc.Protocol, error) {
	var protoPtrs []uint64
	protRefs := make(map[uint64]*objc.Protocol)

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_protorefs"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_protorefs: %v", err)
				}

				protoPtrs = make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &protoPtrs); err != nil {
					return nil, fmt.Errorf("failed to read super ref pointers: %v", err)
				}

				for idx, ptr := range protoPtrs {
					proto, err := f.getObjcProtocol(f.vma.Convert(ptr))
					if err != nil {
						return nil, fmt.Errorf("failed to read objc_class_t at superref ptr: %#x; %v", ptr, err)
					}
					protRefs[sec.Addr+uint64(idx*sizeOfInt64)] = proto
				}
				return protRefs, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain a __objc_protorefs section")
}

func (f *File) GetObjCSelectorReferences() (map[uint64]*objc.Selector, error) {
	var selPtrs []uint64
	selRefs := make(map[uint64]*objc.Selector)

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_selrefs"); sec != nil {
				if sec.Size == 0 {
					return nil, fmt.Errorf("%s.%s section has size 0", sec.Seg, sec.Name)
				}

				dat, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __objc_selrefs: %v", err)
				}

				selPtrs = make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &selPtrs); err != nil {
					return nil, fmt.Errorf("failed to read selector ref pointers: %v", err)
				}

				for idx, sel := range selPtrs {
					selName, err := f.GetCString(f.vma.Convert(sel))
					if err != nil {
						return nil, fmt.Errorf("failed to read cstring: %v", err)
					}
					selRefs[sec.Addr+uint64(idx*sizeOfInt64)] = &objc.Selector{
						VMAddr: f.vma.Convert(sel),
						Name:   selName,
					}
				}
				return selRefs, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain a __objc_selrefs section")
}
