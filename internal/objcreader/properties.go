package objcreader

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types/objc"
)

// GetObjCIvars returns the Objective-C instance variables
func (f *Reader) GetObjCIvars(vmaddr uint64) ([]objc.Ivar, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCIvars"); err != nil {
		return nil, err
	}

	return f.getObjCIvarsWithSwift(vmaddr, false)
}

func (f *Reader) readObjCIvarOffset(addr uint64) (uint32, error) {
	if addr == 0 {
		return 0, nil
	}
	if !f.HasFileData(addr, 4) {
		if f.HasZeroFillData(addr, 4) {
			return 0, nil
		}
		return 0, fmt.Errorf("address %#x is not file-backed or zero-filled", addr)
	}
	if err := f.DataReader().SeekToAddr(addr); err != nil {
		return 0, err
	}
	var offset uint32
	err := binary.Read(f.DataReader(), f.ByteOrder(), &offset)
	if err == io.EOF {
		return 0, nil // The caller's reader can expose runtime-filled storage.
	}
	return offset, err
}

func (f *Reader) getObjCIvarsWithSwift(vmaddr uint64, allowSwift bool) ([]objc.Ivar, error) {

	var ivarsList objc.IvarList
	var ivars []objc.Ivar
	if err := f.CheckFileData(vmaddr, uint64(binary.Size(ivarsList))); err != nil {
		return nil, fmt.Errorf("failed to read objc_ivar_list_t: %w", err)
	}

	if err := f.DataReader().SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc_ivar_list_t at %#x: %v", vmaddr, err)
	}

	if err := binary.Read(f.DataReader(), f.ByteOrder(), &ivarsList); err != nil {
		return nil, fmt.Errorf("failed to read objc_ivar_list_t: %v", err)
	}
	if err := f.checkObjCListData(vmaddr, uint64(binary.Size(ivarsList)),
		uint64(ivarsList.Count), uint64(binary.Size(objc.IvarT{}))); err != nil {
		return nil, fmt.Errorf("failed to read objc_ivar_list_t: %w", err)
	}

	ivs := make([]objc.IvarT, ivarsList.Count)
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &ivs); err != nil {
		return nil, fmt.Errorf("failed to read objc_ivar_list_t: %v", err)
	}

	// FIXME: what ARE these alignments ?
	for _, ivar := range ivs {
		ivar.Offset = f.ConvertPointer(ivar.Offset)
		ivar.NameVMAddr = f.ConvertPointer(ivar.NameVMAddr)
		ivar.TypesVMAddr = f.ConvertPointer(ivar.TypesVMAddr)

		o, err := f.readObjCIvarOffset(ivar.Offset)
		if err != nil {
			return nil, fmt.Errorf("failed to read ivar.offset at %#x: %w", ivar.Offset, err)
		}
		n, err := f.GetCString(ivar.NameVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read ivar name cstring: %v", err)
		}
		t, err := f.getCStringWithFallback(ivar.TypesVMAddr, "ivar type", allowSwift)
		if err != nil {
			return nil, fmt.Errorf("failed to read ivar types cstring: %v", err)
		}
		if allowSwift {
			t = NormalizeSwiftIvarTypeEncoding(t)
		}
		if allowSwift && t == "" {
			if guess, ok := f.SwiftASCIITypeGuess(ivar.TypesVMAddr); ok {
				t = guess
			}
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

func NormalizeSwiftIvarTypeEncoding(enc string) string {
	enc = strings.TrimSpace(enc)
	if enc == "" || !strings.Contains(enc, ":") {
		return enc
	}

	typ, rest, ok := objc.CutType(enc)
	if !ok || rest == "" {
		return enc
	}

	stackSizePrefixLen := leadingDecimalLen(rest)
	if stackSizePrefixLen == 0 {
		return enc
	}

	if strings.Contains(rest[stackSizePrefixLen:], ":") {
		return typ
	}

	return enc
}

func leadingDecimalLen(input string) int {
	length := 0
	for length < len(input) && input[length] >= '0' && input[length] <= '9' {
		length++
	}
	return length
}

// GetObjCProperties returns the Objective-C properties
func (f *Reader) GetObjCProperties(vmaddr uint64) ([]objc.Property, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCProperties"); err != nil {
		return nil, err
	}

	return f.getObjCPropertiesWithSwift(vmaddr, false)
}

func (f *Reader) getObjCPropertiesWithSwift(
	vmaddr uint64, allowSwift bool,
) ([]objc.Property, error) {

	var propList objc.PropertyList
	var objcProperties []objc.Property
	if err := f.CheckFileData(vmaddr, uint64(binary.Size(propList))); err != nil {
		return nil, fmt.Errorf("failed to read objc_property_list_t: %w", err)
	}

	if err := f.DataReader().SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc_property_list_t at %#x: %v", vmaddr, err)
	}

	if err := binary.Read(f.DataReader(), f.ByteOrder(), &propList); err != nil {
		return nil, fmt.Errorf("failed to read objc_property_list_t: %v", err)
	}
	if err := f.checkObjCListData(vmaddr, uint64(binary.Size(propList)),
		uint64(propList.Count), uint64(binary.Size(objc.PropertyT{}))); err != nil {
		return nil, fmt.Errorf("failed to read objc_property_list_t: %w", err)
	}

	properties := make([]objc.PropertyT, propList.Count)
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &properties); err != nil {
		return nil, fmt.Errorf("failed to read objc_property_t: %v", err)
	}

	for _, prop := range properties {
		prop.NameVMAddr = f.ConvertPointer(prop.NameVMAddr)
		prop.AttributesVMAddr = f.ConvertPointer(prop.AttributesVMAddr)

		name, err := f.getCStringWithFallback(prop.NameVMAddr, "property name", allowSwift)
		if err != nil {
			return nil, fmt.Errorf("failed to read prop name cstring: %v", err)
		}
		attrib, err := f.getCStringWithFallback(prop.AttributesVMAddr, "property attributes", allowSwift)
		if err != nil {
			return nil, fmt.Errorf("failed to read prop attributes cstring: %v", err)
		}
		objcProperties = append(objcProperties, objc.Property{
			PropertyT:         prop,
			Name:              name,
			EncodedAttributes: attrib,
		})
	}

	return objcProperties, nil
}

func matchSwiftFieldType(name string, fieldMap map[string]string) (string, bool) {
	if fieldMap == nil {
		return "", false
	}
	if typ, ok := fieldMap[name]; ok {
		return typ, true
	}
	trimmed := strings.TrimPrefix(name, "_")
	if typ, ok := fieldMap[trimmed]; ok {
		return typ, true
	}
	return "", false
}
