package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/blacktop/go-macho/types"
)

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

func (f *File) GetObjCInfo() types.ObjCInfo {
	var oInfo types.ObjCInfo

	ptrSize := uint64(8)
	for _, sec := range f.FileTOC.Sections {
		if strings.HasPrefix(sec.SectionHeader.Seg, "__DATA") {
			if strings.EqualFold(sec.Name, "__objc_selrefs") {
				oInfo.SelRefCount += sec.SectionHeader.Size / ptrSize
			} else if strings.EqualFold(sec.Name, "__objc_classlist") {
				oInfo.ClassDefCount += sec.SectionHeader.Size / ptrSize
			} else if strings.EqualFold(sec.Name, "__objc_protolist") {
				oInfo.ProtocolDefCount += sec.SectionHeader.Size / ptrSize
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

func (f *File) GetObjcImageInfo() types.ObjCImageInfo {
	var imgInfo types.ObjCImageInfo
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_imageinfo"); sec != nil {
				dat, err := sec.Data()
				if err != nil {
					log.Fatal(err.Error())
				}
				r := bytes.NewReader(dat)
				err = binary.Read(r, f.ByteOrder, &imgInfo)
				if err != nil {
					log.Fatal(err.Error())
				}
				fmt.Printf("%#v\n", imgInfo)
			}
		}
	}
	return imgInfo
}

// func (f *File) GetObjCMethodNames(r io.ReaderAt) []string {
func (f *File) GetObjCMethodNames() []string {
	var methods []string

	for _, sec := range f.FileTOC.Sections {
		if sec.Seg == "__TEXT" && sec.Name == "__objc_methname" {

			off, err := f.GetOffset(sec.Addr)
			if err != nil {
				return nil
			}

			stringPool := make([]byte, sec.Size)

			_, err = f.sr.ReadAt(stringPool, int64(off))
			if err != nil {
				log.Fatal(err.Error())
			}

			r := bytes.NewBuffer(stringPool[:])

			for {
				s, err := r.ReadString('\x00')
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Fatal(err.Error())
				}
				methods = append(methods, strings.Trim(s, "\x00"))
			}
		}
	}
	return methods
}

func (f *File) GetObjCClasses() []string {
	var classes []string

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_classlist"); sec != nil {
				dat, err := sec.Data()
				if err != nil {
					log.Fatal(err.Error())
				}
				r := bytes.NewReader(dat)
				ptrs := make([]uint64, sec.Size/8)
				err = binary.Read(r, f.ByteOrder, &ptrs)
				if err != nil {
					log.Fatal(err.Error())
				}
				for _, ptr := range ptrs {
					off, err := f.GetOffset(ptr)
					if err != nil {
						return nil
					}
					f.sr.Seek(int64(off), io.SeekStart)
					var classPtr types.SwiftClassMetadata64
					binary.Read(f.sr, f.ByteOrder, &classPtr)
					fmt.Printf("%#v\n", classPtr)
					if classPtr.SuperclassVmAddr > 0 {
						superOff, err := f.GetOffset(classPtr.SuperclassVmAddr)
						if err != nil {
							return nil
						}
						f.sr.Seek(int64(superOff), io.SeekStart)
						var superClassPtr types.SwiftClassMetadata64
						binary.Read(f.sr, f.ByteOrder, &superClassPtr)
						fmt.Printf("%#v\n", superClassPtr)
					}
				}
			}
		}
	}
	return classes
}

func (f *File) GetObjCCategories() []string {
	var categories []string

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_catlist"); sec != nil {
				dat, err := sec.Data()
				if err != nil {
					log.Fatal(err.Error())
				}
				r := bytes.NewReader(dat)
				ptrs := make([]uint64, sec.Size/8)
				err = binary.Read(r, f.ByteOrder, &ptrs)
				if err != nil {
					log.Fatal(err.Error())
				}
				for _, ptr := range ptrs {
					off, err := f.GetOffset(ptr)
					if err != nil {
						return nil
					}
					f.sr.Seek(int64(off), io.SeekStart)
					var catPtr types.ObjCCategory
					binary.Read(f.sr, f.ByteOrder, &catPtr)
					fmt.Printf("%#v\n", catPtr)
				}
			}
		}
	}

	return categories
}

func (f *File) GetObjCProtocols() []string {
	var protocols []string

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_protolist"); sec != nil {
				dat, err := sec.Data()
				if err != nil {
					log.Fatal(err.Error())
				}
				r := bytes.NewReader(dat)
				ptrs := make([]uint64, sec.Size/8)
				err = binary.Read(r, f.ByteOrder, &ptrs)
				if err != nil {
					log.Fatal(err.Error())
				}
				for _, ptr := range ptrs {
					off, err := f.GetOffset(ptr)
					if err != nil {
						return nil
					}
					f.sr.Seek(int64(off), io.SeekStart)
					var protoPtr types.ObjCProtocol
					binary.Read(f.sr, f.ByteOrder, &protoPtr)
					fmt.Printf("%#v\n", protoPtr)
					f.GetObjCMethods(protoPtr.InstanceMethodsVMAddr)
					f.GetObjCMethods(protoPtr.ClassMethodsVMAddr)
					f.GetObjCMethods(protoPtr.OptionalInstanceMethodsVMAddr)
					f.GetObjCMethods(protoPtr.OptionalClassMethodsVMAddr)
				}
			}
		}
	}

	return protocols
}

func (f *File) GetObjCMethods(vmAddr uint64) []types.ObjCMethod {
	if vmAddr == 0 {
		return nil
	}

	var objcMethods []types.ObjCMethod

	off, err := f.GetOffset(vmAddr)
	if err != nil {
		return nil
	}

	f.sr.Seek(int64(off), io.SeekStart)
	var methodList types.MethodList_t
	binary.Read(f.sr, f.ByteOrder, &methodList)
	fmt.Printf("%#v\n", methodList)

	// f.sr.Seek(-8, io.SeekCurrent)
	methods := make([]types.Method_t, methodList.Count)
	err = binary.Read(f.sr, f.ByteOrder, &methods)
	if err != nil {
		return nil
	}
	fmt.Printf("%#v\n", methods)

	for _, method := range methods {
		s, err := f.GetCString(method.NameVMAddr)
		if err != nil {
			return nil
		}
		fmt.Println(s)
		objcMethods = append(objcMethods, types.ObjCMethod{})
	}

	return objcMethods
}

func (f *File) GetObjCSelectorReferences() []uint64 {
	var selRefs []uint64

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_selrefs"); sec != nil {
				dat, err := sec.Data()
				if err != nil {
					log.Fatal(err.Error())
				}
				r := bytes.NewReader(dat)
				selRefs = make([]uint64, sec.Size/8)
				err = binary.Read(r, f.ByteOrder, &selRefs)
				if err != nil {
					log.Fatal(err.Error())
				}
			}
		}
	}

	return selRefs
}
