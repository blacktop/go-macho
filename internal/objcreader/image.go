package objcreader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
)

// HasObjC returns true if MachO contains Objective-C metadata.
func (f *Reader) HasObjC() bool {
	return f.hasObjCNonFragileRuntime() || f.hasObjCFragileRuntime()
}

// HasPlusLoadMethod returns true if MachO contains a __objc_nlclslist or __objc_nlcatlist section
func (f *Reader) HasPlusLoadMethod() bool {
	// TODO add the old way of detecting from dyld3/MachOAnalyzer.cpp
	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			if sec := f.Section(s, "__objc_nlclslist"); sec != nil {
				return true
			}
			if sec := f.Section(s, "__objc_nlcatlist"); sec != nil {
				return true
			}
		}
	}
	return false
}

// HasObjCMessageReferences returns true if MachO contains a __objc_msgrefs section
func (f *Reader) HasObjCMessageReferences() bool {
	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			if sec := f.Section(s, "__objc_msgrefs"); sec != nil {
				return true
			}
		}
	}
	if sec := f.Section("__OBJC", "__message_refs"); sec != nil {
		return true
	}
	return false
}

// GetObjCToc returns a table of contents of the ObjC objects in the MachO
func (f *Reader) GetObjCToc() objc.Toc {
	var oInfo objc.Toc
	for _, sec := range f.Sections() {
		if strings.HasPrefix(sec.Seg, "__DATA") {
			switch sec.Name {
			case "__objc_classlist":
				oInfo.ClassList = sec.Size / f.PointerSize()
			case "__objc_nlclslist":
				oInfo.NonLazyClassList = sec.Size / f.PointerSize()
			case "__objc_catlist":
				oInfo.CatList = sec.Size / f.PointerSize()
			case "__objc_nlcatlist":
				oInfo.NonLazyCatList = sec.Size / f.PointerSize()
			case "__objc_protolist":
				oInfo.ProtoList = sec.Size / f.PointerSize()
			case "__objc_classrefs":
				oInfo.ClassRefs = sec.Size / f.PointerSize()
			case "__objc_superrefs":
				oInfo.SuperRefs = sec.Size / f.PointerSize()
			case "__objc_selrefs":
				oInfo.SelRefs = sec.Size / f.PointerSize()
			}
		} else if strings.EqualFold(sec.Seg, "__OBJC") {
			if strings.EqualFold(sec.Name, "__message_refs") {
				oInfo.SelRefs += sec.Size / 4
			} else if strings.EqualFold(sec.Name, "__class") {
				oInfo.ClassList += sec.Size / 48
			} else if strings.EqualFold(sec.Name, "__protocol") {
				oInfo.ProtoList += sec.Size / 20
			}
		}
	}
	return oInfo
}

// GetObjCImageInfo returns the parsed __objc_imageinfo data
func (f *Reader) GetObjCImageInfo() (*objc.ImageInfo, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCImageInfo"); err != nil {
		return nil, err
	}

	var imgInfo objc.ImageInfo
	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			if sec := f.Section(s, "__objc_imageinfo"); sec != nil {
				off, err := f.GetOffset(sec.Addr)
				if err != nil {
					return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
				}
				if _, err := f.DataReader().Seek(int64(off), io.SeekStart); err != nil {
					return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
				}

				dat := make([]byte, sec.Size)
				if err := binary.Read(f.DataReader(), f.ByteOrder(), dat); err != nil {
					return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
				}

				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder(), &imgInfo); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", imgInfo, err)
				}

				return &imgInfo, nil
			}
		}
	}
	return nil, fmt.Errorf(
		"macho does not contain __objc_imageinfo section: %w",
		ErrObjcSectionNotFound)
}

// GetObjCClassNames returns a map of section data virtual memory address to their class names
func (f *Reader) GetObjCClassNames() (map[uint64]string, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClassNames"); err != nil {
		return nil, err
	}

	class2vmaddr := make(map[uint64]string)

	// Names for locally implemented classes
	if sec := f.Section("__TEXT", "__objc_classname"); sec != nil {
		if err := f.DataReader().SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.DataReader(), f.ByteOrder(), dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewBuffer(dat)

		for {
			s, err := r.ReadString('\x00')
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read from class name string pool: %v", err)
			}

			if len(strings.Trim(s, "\x00")) > 0 && types.IsASCII(strings.Trim(s, "\x00")) {
				class2vmaddr[sec.Addr+(sec.Size-uint64(r.Len()+len(s)))] = strings.Trim(s, "\x00")
			}
		}
	}

	return class2vmaddr, nil
}

// GetObjCMethodNames returns a map of section data virtual memory addresses to their method names
func (f *Reader) GetObjCMethodNames() (map[uint64]string, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCMethodNames"); err != nil {
		return nil, err
	}

	meth2vmaddr := make(map[uint64]string)

	// Method names for locally implemented methods
	if sec := f.Section("__TEXT", "__objc_methname"); sec != nil {
		if err := f.DataReader().SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.DataReader(), f.ByteOrder(), dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewBuffer(dat)

		for {
			s, err := r.ReadString('\x00')
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read from method name string pool: %v", err)
			}

			if len(strings.Trim(s, "\x00")) > 0 && types.IsASCII(strings.Trim(s, "\x00")) {
				meth2vmaddr[sec.Addr+(sec.Size-uint64(r.Len()+len(s)))] = strings.Trim(s, "\x00")
			}
		}
	}

	return meth2vmaddr, nil
}
