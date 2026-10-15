package objcreader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

// GetObjCCategories returns the Objective-C categories in __objc_catlist.
func (f *Reader) GetObjCCategories() ([]objc.Category, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCCategories"); err != nil {
		return nil, err
	}
	var categories []objc.Category
	for _, name := range f.SegmentNames() {
		if !strings.HasPrefix(name, "__DATA") {
			continue
		}
		sec := f.Section(name, "__objc_catlist")
		if sec == nil {
			continue
		}
		ptrs, err := f.readSectionPointers(sec)
		if err != nil {
			return nil, err
		}
		for _, ptr := range ptrs {
			category, err := f.readObjCCategory(f.ConvertPointer(ptr))
			if err != nil {
				return nil, err
			}
			categories = append(categories, *category)
		}
	}
	return categories, nil
}

// readSectionPointers reads a section that holds an array of raw pointers.
func (f *Reader) readSectionPointers(sec *types.Section) ([]uint64, error) {
	if err := f.DataReader().SeekToAddr(sec.Addr); err != nil {
		return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
	}
	data := make([]byte, sec.Size)
	if err := binary.Read(f.DataReader(), f.ByteOrder(), data); err != nil {
		return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
	}
	ptrs := make([]uint64, sec.Size/f.PointerSize())
	if err := binary.Read(bytes.NewReader(data), f.ByteOrder(), &ptrs); err != nil {
		return nil, fmt.Errorf("failed to read %s.%s pointers: %v", sec.Seg, sec.Name, err)
	}
	return ptrs, nil
}

func (f *Reader) readObjCCategory(vmaddr uint64) (*objc.Category, error) {
	offset, err := f.GetOffset(vmaddr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
	}
	if _, err := f.DataReader().Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to category_t at %#x: %v", vmaddr, err)
	}
	var ptr objc.CategoryT
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &ptr); err != nil {
		return nil, fmt.Errorf("failed to read %T: %v", ptr, err)
	}
	category := &objc.Category{VMAddr: vmaddr}
	ptr.NameVMAddr = f.ConvertPointer(ptr.NameVMAddr)
	category.Name, err = f.GetCString(ptr.NameVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}
	hasClass := ptr.ClsVMAddr != 0
	if hasClass {
		ptr.ClsVMAddr = f.ConvertPointer(ptr.ClsVMAddr)
	}
	category.Class, err = f.objcCategoryClass(vmaddr, ptr.ClsVMAddr, hasClass)
	if err != nil {
		return nil, err
	}
	if err := f.readObjCCategoryContents(category, &ptr); err != nil {
		return nil, err
	}
	category.CategoryT = ptr
	return category, nil
}

func (f *Reader) readObjCCategoryContents(category *objc.Category, ptr *objc.CategoryT) error {
	if err := f.readObjCCategoryMethods(category, ptr); err != nil {
		return err
	}
	var err error
	if ptr.ProtocolsVMAddr > 0 {
		ptr.ProtocolsVMAddr = f.ConvertPointer(ptr.ProtocolsVMAddr)
		category.Protocols, err = f.parseObjcProtocolList(ptr.ProtocolsVMAddr)
		if err != nil {
			return fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}
	if ptr.InstancePropertiesVMAddr > 0 {
		ptr.InstancePropertiesVMAddr = f.ConvertPointer(ptr.InstancePropertiesVMAddr)
		allowSwift := category.Class != nil && category.Class.IsSwift()
		category.Properties, err = f.getObjCPropertiesWithSwift(
			ptr.InstancePropertiesVMAddr, allowSwift)
		if err != nil {
			return fmt.Errorf("failed to get instance properties at vmaddr: %#x; %v",
				ptr.InstancePropertiesVMAddr, err)
		}
	}
	return nil
}

func (f *Reader) readObjCCategoryMethods(category *objc.Category, ptr *objc.CategoryT) error {
	var err error
	if ptr.InstanceMethodsVMAddr > 0 {
		ptr.InstanceMethodsVMAddr = f.ConvertPointer(ptr.InstanceMethodsVMAddr)
		category.InstanceMethods, err = f.GetObjCMethods(ptr.InstanceMethodsVMAddr)
		if err != nil {
			return fmt.Errorf("failed to get instance methods at vmaddr: %#x; %v",
				ptr.InstanceMethodsVMAddr, err)
		}
	}
	if ptr.ClassMethodsVMAddr > 0 {
		ptr.ClassMethodsVMAddr = f.ConvertPointer(ptr.ClassMethodsVMAddr)
		category.ClassMethods, err = f.GetObjCMethods(ptr.ClassMethodsVMAddr)
		if err != nil {
			return fmt.Errorf("failed to get class methods at vmaddr: %#x; %v",
				ptr.ClassMethodsVMAddr, err)
		}
	}
	return nil
}

func (f *Reader) objcCategoryClass(
	categoryAddr, classAddr uint64, hasClass bool,
) (*objc.Class, error) {
	if !hasClass {
		var ptr objc.CategoryT
		return f.objcCategoryBind(categoryAddr+uint64(unsafe.Offsetof(ptr.ClsVMAddr)), nil)
	}
	if value, ok := f.GetObjC(classAddr); ok {
		return value.(*objc.Class), nil
	}
	class, err := f.GetObjCClass(classAddr)
	if err == nil {
		f.PutObjC(classAddr, class)
		return class, nil
	}
	if !f.HasFixups() {
		return &objc.Class{}, nil
	}
	return f.objcCategoryBind(classAddr, err)
}

func (f *Reader) objcCategoryBind(addr uint64, classErr error) (*objc.Class, error) {
	name, err := f.GetBindName(addr)
	if err == nil {
		return &objc.Class{Name: strings.TrimPrefix(name, "_OBJC_CLASS_$_")}, nil
	}
	if f.BindInfoUnavailable(err) {
		return &objc.Class{}, nil
	}
	if classErr == nil {
		return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %v",
			addr, err)
	}
	return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %w",
		addr, errors.Join(classErr, err))
}

// GetObjCNonLazyCategories returns an array of Objective-C classes that implement +load
func (f *Reader) GetObjCNonLazyCategories() ([]objc.Category, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCNonLazyCategories"); err != nil {
		return nil, err
	}

	var cats []objc.Category

	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			// An array of pointers to classes who implement +load
			if sec := f.Section(s, "__objc_nlcatlist"); sec != nil {
				ptrs, err := f.readSectionPointers(sec)
				if err != nil {
					return nil, err
				}
				for _, ptr := range ptrs {
					ptr = f.ConvertPointer(ptr)
					if c, ok := f.GetObjC(ptr); ok {
						cats = append(cats, *c.(*objc.Category))
					} else {
						cat, err := f.parseCategory(ptr)
						if err != nil {
							return nil, fmt.Errorf("failed to read non-lazy category_t at vmaddr %#x: %v", ptr, err)
						}
						cats = append(cats, *cat)
						f.PutObjC(ptr, cat)
					}
				}
			}
		}
	}

	return cats, nil
}

func (f *Reader) parseCategory(vmaddr uint64) (*objc.Category, error) {

	if err := f.DataReader().SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc category vmaddr: %#x; %v", vmaddr, err)
	}

	var categoryPtr objc.CategoryT
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &categoryPtr); err != nil {
		return nil, fmt.Errorf("failed to read %T: %v", categoryPtr, err)
	}

	categoryPtr.NameVMAddr = f.ConvertPointer(categoryPtr.NameVMAddr)
	categoryPtr.ClsVMAddr = f.ConvertPointer(categoryPtr.ClsVMAddr)
	categoryPtr.InstanceMethodsVMAddr = f.ConvertPointer(categoryPtr.InstanceMethodsVMAddr)
	categoryPtr.ClassMethodsVMAddr = f.ConvertPointer(categoryPtr.ClassMethodsVMAddr)
	categoryPtr.ProtocolsVMAddr = f.ConvertPointer(categoryPtr.ProtocolsVMAddr)
	categoryPtr.InstancePropertiesVMAddr = f.ConvertPointer(categoryPtr.InstancePropertiesVMAddr)

	name, err := f.GetCString(categoryPtr.NameVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	return &objc.Category{
		Name:      name,
		VMAddr:    vmaddr,
		CategoryT: categoryPtr,
	}, nil
}
