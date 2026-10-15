package objcreader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"github.com/blacktop/go-macho/types/objc"
)

// MethodHandler receives the method entry's VM address in either list format.
type MethodHandler func(uint64, objc.Method, *bool)

// ForEachMethod decodes the method list at addr and calls handler for each entry
// until handler sets stop.
func (f *Reader) ForEachMethod(addr uint64, handler MethodHandler) error {
	list, err := f.readObjCMethodList(addr)
	if err != nil {
		return err
	}
	if list.Count == 0 {
		return nil
	}
	if list.UsesRelativeOffsets() {
		return f.forEachRelativeObjCMethod(addr, list, handler)
	}
	return f.forEachAbsoluteObjCMethod(addr, list, handler)
}

func (f *Reader) readObjCMethodList(addr uint64) (objc.MethodList, error) {
	var list objc.MethodList
	if err := f.CheckFileData(addr, uint64(binary.Size(list))); err != nil {
		return list, fmt.Errorf("failed to read method_list_t: %w", err)
	}
	if err := f.DataReader().SeekToAddr(addr); err != nil {
		return list, fmt.Errorf("failed to seek to method_list_t at %#x: %w", addr, err)
	}
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &list); err != nil {
		return list, fmt.Errorf("failed to read method_list_t at %#x: %w", addr, err)
	}
	entrySize := uint64(binary.Size(objc.MethodT{}))
	if list.UsesRelativeOffsets() {
		entrySize = uint64(binary.Size(objc.RelativeMethodT{}))
	}
	if err := f.checkObjCListData(addr, uint64(binary.Size(list)),
		uint64(list.Count), entrySize); err != nil {
		return list, fmt.Errorf("failed to read method_list_t: %w", err)
	}
	return list, nil
}

func (f *Reader) forEachRelativeObjCMethod(
	addr uint64, list objc.MethodList, handler MethodHandler,
) error {
	if list.UsesDirectOffsetsToSelectors() && f.RelativeSelectorBase() == 0 {
		f.objcSelectorBaseUnavailable = true
		return fmt.Errorf("%w (method list %#x)", ErrObjCSelectorBaseUnavailable, addr)
	}
	base := addr + uint64(binary.Size(list))
	methods := make([]objc.RelativeMethodT, list.Count)
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &methods); err != nil {
		return fmt.Errorf("failed to read relative_method_t: %w", err)
	}
	for idx, raw := range methods {
		methodAddr := int64(base) + int64(uint32(idx)*list.EntSize())
		method, err := f.readRelativeObjCMethod(list, methodAddr, raw)
		if err != nil {
			return err
		}
		stop := false
		handler(uint64(methodAddr), method, &stop)
		if stop {
			break
		}
	}
	return nil
}

func (f *Reader) relativeObjCSelector(
	list objc.MethodList, methodAddr int64, raw objc.RelativeMethodT,
) (uint64, error) {
	if list.UsesDirectOffsetsToSelectors() {
		base := f.RelativeSelectorBase()
		return base + uint64(uint32(raw.NameOffset)), nil
	}
	fieldAddr := uint64(methodAddr + int64(unsafe.Offsetof(raw.NameOffset)))
	indirect, err := objcRelativeAddress(fieldAddr, raw.NameOffset)
	if err != nil {
		return 0, err
	}
	if err := f.CheckFileData(indirect, 8); err != nil {
		return 0, err
	}
	return f.GetPointerAtAddress(indirect)
}

func (f *Reader) readRelativeObjCMethod(
	list objc.MethodList, addr int64, raw objc.RelativeMethodT,
) (objc.Method, error) {
	var method objc.Method
	var err error
	method.NameVMAddr, err = f.relativeObjCSelector(list, addr, raw)
	if err != nil {
		return method, fmt.Errorf("failed to read relative_method_t name pointer: %w", err)
	}
	method.NameLocationVMAddr = uint64(addr + int64(unsafe.Offsetof(raw.NameOffset)))
	typesAddr := addr + int64(unsafe.Offsetof(raw.TypesOffset))
	impAddr := addr + int64(unsafe.Offsetof(raw.ImpOffset))
	if list.UsesDirectOffsetsToTypes() && f.RelativeSelectorBase() != 0 {
		base := f.RelativeSelectorBase()
		method.TypesVMAddr = base + uint64(uint32(raw.TypesOffset))
	} else {
		method.TypesVMAddr = uint64(typesAddr + int64(raw.TypesOffset))
	}
	method.ImpVMAddr = uint64(impAddr + int64(raw.ImpOffset))
	method.Name, err = f.getCStringWithFallback(method.NameVMAddr, "selector", false)
	if err != nil {
		return method, fmt.Errorf("failed to read relative_method_t name cstring: %w", err)
	}
	method.Types, err = f.getCStringWithFallback(method.TypesVMAddr, "method types", false)
	if err != nil {
		return method, fmt.Errorf("failed to read relative_method_t types cstring: %w", err)
	}
	return method, nil
}

func (f *Reader) forEachAbsoluteObjCMethod(
	addr uint64, list objc.MethodList, handler MethodHandler,
) error {
	base := addr + uint64(binary.Size(list))
	methods := make([]objc.MethodT, list.Count)
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &methods); err != nil {
		return fmt.Errorf("failed to read method_t(s): %w", err)
	}
	for idx, raw := range methods {
		method, err := f.readAbsoluteObjCMethod(raw)
		if err != nil {
			return err
		}
		stop := false
		handler(base+uint64(idx*binary.Size(raw)), method, &stop)
		if stop {
			break
		}
	}
	return nil
}

func (f *Reader) readAbsoluteObjCMethod(raw objc.MethodT) (objc.Method, error) {
	method := objc.Method{
		NameVMAddr:  f.ConvertPointer(raw.NameVMAddr),
		TypesVMAddr: f.ConvertPointer(raw.TypesVMAddr),
		ImpVMAddr:   f.ConvertPointer(raw.ImpVMAddr),
	}
	var err error
	method.Name, err = f.getCStringWithFallback(method.NameVMAddr, "selector", false)
	if err != nil {
		return method, fmt.Errorf("failed to read method_t name cstring: %w", err)
	}
	method.Types, err = f.getCStringWithFallback(method.TypesVMAddr, "method types", false)
	if err != nil {
		return method, fmt.Errorf("failed to read method_t types cstring: %w", err)
	}
	return method, nil
}

func (f *Reader) GetObjCMethods(vmaddr uint64) ([]objc.Method, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCMethods"); err != nil {
		return nil, err
	}

	if c, ok := f.GetObjC(vmaddr); ok {
		return c.([]objc.Method), nil
	}

	var methods []objc.Method

	if err := f.ForEachMethod(vmaddr, func(u uint64, m objc.Method, b *bool) {
		methods = append(methods, m)
	}); err != nil {
		return nil, fmt.Errorf("failed to read methods at vmaddr %#x: %v", vmaddr, err)
	}

	f.PutObjC(vmaddr, methods)

	return methods, nil
}

// GetObjCMethodLists parses the method lists in the __objc_methlist section
func (f *Reader) GetObjCMethodLists() ([]objc.Method, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCMethodLists"); err != nil {
		return nil, err
	}

	var methods []objc.Method
	var methodList objc.MethodList
	var nextMethodListOffset uint64

	if sec := f.Section("__TEXT", "__objc_methlist"); sec != nil {
		if err := f.DataReader().SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.DataReader(), f.ByteOrder(), dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		var mladdrs []uint64

		for {
			currOffset, _ := r.Seek(0, io.SeekCurrent)
			currAddr := sec.Addr + uint64(currOffset)

			err := binary.Read(r, f.ByteOrder(), &methodList)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read method_list_t: %v", err)
			}

			mladdrs = append(mladdrs, currAddr)
			currOffset, _ = r.Seek(0, io.SeekCurrent)

			if methodList.UsesRelativeOffsets() {
				nextMethodListOffset = uint64(currOffset +
					int64(methodList.Count)*int64(binary.Size(objc.RelativeMethodT{})))
				nextMethodListOffset += nextMethodListOffset % f.PointerSize() // pointer align
			} else {
				nextMethodListOffset = uint64(currOffset +
					int64(methodList.Count)*int64(binary.Size(objc.MethodT{})))
				nextMethodListOffset += nextMethodListOffset % f.PointerSize() // pointer align
			}
			// skip to next method_list_t
			if _, err := r.Seek(int64(nextMethodListOffset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to next method_list_t: %v", err)
			}
		}

		for _, mladdr := range mladdrs {
			if err := f.ForEachMethod(mladdr, func(u uint64, m objc.Method, b *bool) {
				methods = append(methods, m)
			}); err != nil {
				return nil, fmt.Errorf(
					"failed to read methods for method_list_t at vmaddr %#x: %v",
					mladdr, err)
			}
		}
	} else {
		return nil, fmt.Errorf(
			"macho does not contain __objc_methlist section: %w",
			ErrObjcSectionNotFound)
	}

	return methods, nil
}
