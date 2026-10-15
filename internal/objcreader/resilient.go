package objcreader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
	"github.com/blacktop/go-macho/types/swift"
)

// appendObjCResilientClasses follows Swift descriptors to the static class_ro
// data for entries in __objc_stublist. A stub is not an objc_class_t: its isa is
// 1 and its callback materializes the class at runtime. Never execute it.
func (f *Reader) appendObjCResilientClasses(classes []objc.Class) ([]objc.Class, error) {
	stubs, err := f.objcResilientStubs()
	if err != nil {
		return nil, err
	}
	if len(stubs) == 0 {
		return classes, nil
	}
	seen := make(map[string]bool, len(classes))
	for _, class := range classes {
		seen[class.Name] = true
	}
	for _, sec := range f.Sections() {
		if !isSwiftTypeSection(sec) {
			continue
		}
		classes, err = f.appendObjCResilientSection(classes, seen, stubs, sec)
		if err != nil {
			return nil, err
		}
		if len(stubs) == 0 {
			return classes, nil
		}
	}
	// Singleton metadata also uses stubs without resilient descriptor trailers.
	return classes, nil
}

func isSwiftTypeSection(sec *types.Section) bool {
	return sec.Seg == "__TEXT" &&
		(sec.Name == "__swift5_types" || sec.Name == "__swift5_types2")
}

func (f *Reader) objcResilientStubs() (map[uint64]bool, error) {
	stubs := make(map[uint64]bool)
	for _, sec := range f.Sections() {
		if !strings.HasPrefix(sec.Seg, "__DATA") || sec.Name != "__objc_stublist" {
			continue
		}
		if err := f.readObjCResilientStubs(sec, stubs); err != nil {
			return nil, err
		}
	}
	return stubs, nil
}

func (f *Reader) readObjCResilientStubs(sec *types.Section, stubs map[uint64]bool) error {
	if err := f.validateObjCStubSection(sec); err != nil {
		return err
	}
	for off := uint64(0); off < sec.Size; off += 8 {
		if !f.HasFileData(sec.Addr+off, 8) {
			continue
		}
		ptr, err := f.GetSlidPointerAtAddress(sec.Addr + off)
		if err != nil {
			return fmt.Errorf("read Objective-C class stub pointer: %w", err)
		}
		var raw [8]byte
		// Runtime-filled entries are unavailable. Only static Swift stubs qualify.
		available, err := f.readOptionalObjCData(ptr, raw[:])
		if err != nil {
			return fmt.Errorf("read Objective-C class stub isa at %#x: %w", ptr, err)
		}
		if available && f.ByteOrder().Uint64(raw[:]) == 1 {
			stubs[ptr] = true
		}
	}
	return nil
}

func (f *Reader) validateObjCStubSection(sec *types.Section) error {
	if sec.Size == 0 {
		return nil
	}
	if f.PointerSize() != 8 || sec.Size%8 != 0 || sec.Size/8 > 1<<20 {
		return fmt.Errorf("invalid Objective-C class stub section size %#x", sec.Size)
	}
	if sec.Addr > ^uint64(0)-(sec.Size-1) {
		return fmt.Errorf("Objective-C class stub section address overflow")
	}
	return nil
}

func (f *Reader) appendObjCResilientSection(
	classes []objc.Class, seen map[string]bool, stubs map[uint64]bool, sec *types.Section,
) ([]objc.Class, error) {
	if err := validateObjCSwiftTypeSection(sec); err != nil {
		return nil, err
	}
	for off := uint64(0); off < sec.Size; off += 4 {
		class, err := f.objcResilientClassAtSlot(sec.Addr+off, stubs)
		if err != nil {
			return nil, err
		}
		if class != nil && !seen[class.Name] {
			classes = append(classes, *class)
			seen[class.Name] = true
		}
		if len(stubs) == 0 {
			break
		}
	}
	return classes, nil
}

func validateObjCSwiftTypeSection(sec *types.Section) error {
	if sec.Size%4 != 0 || sec.Size/4 > 1<<20 {
		return fmt.Errorf("invalid Swift type section size %#x", sec.Size)
	}
	if sec.Size != 0 && sec.Addr > ^uint64(0)-(sec.Size-1) {
		return fmt.Errorf("swift type section address overflow")
	}
	return nil
}

func (f *Reader) objcResilientClassAtSlot(
	slot uint64, stubs map[uint64]bool,
) (*objc.Class, error) {
	addr, available, err := f.objcResilientTypeAddress(slot)
	if err != nil || !available {
		return nil, err
	}
	return f.recoverObjCResilientClass(addr, stubs)
}

func (f *Reader) objcResilientTypeAddress(slot uint64) (uint64, bool, error) {
	var raw [4]byte
	available, err := f.readOptionalObjCData(slot, raw[:])
	if !available {
		return 0, false, err
	}
	addr, err := objcRelativeAddress(slot, int32(f.ByteOrder().Uint32(raw[:])))
	if err != nil {
		return 0, false, err
	}
	if addr&1 != 0 {
		if err := f.CheckFileData(addr&^1, 8); err != nil {
			return 0, false, nil
		}
		addr, err = f.GetPointerAtAddress(addr &^ 1)
		if err != nil {
			return 0, false, err
		}
	}
	return addr, true, nil
}

func (f *Reader) recoverObjCResilientClass(
	addr uint64, stubs map[uint64]bool,
) (*objc.Class, error) {
	c, err := f.readObjCResilientType(addr)
	if err != nil {
		return nil, fmt.Errorf("read resilient class descriptor at %#x: %w", addr, err)
	}
	if c.ObjCResilientClassStubInfo == nil {
		return nil, nil
	}
	ref := c.ObjCResilientClassStubInfo.Stub
	stub, err := objcRelativeAddress(ref.Address, ref.RelOff)
	if err != nil {
		return nil, err
	}
	if !stubs[stub] {
		return nil, nil
	}
	class, err := f.readObjCResilientClass(c, stub)
	if err != nil {
		return nil, fmt.Errorf("read resilient class at %#x: %w", addr, err)
	}
	if class != nil {
		f.PutObjC(stub, class)
	}
	delete(stubs, stub)
	return class, nil
}

func (f *Reader) readObjCResilientType(addr uint64) (swift.Class, error) {
	var c swift.Class
	var raw [4]byte
	available, err := f.readOptionalObjCData(addr, raw[:])
	if !available {
		return c, err
	}
	flags := swift.ContextDescriptorFlags(f.ByteOrder().Uint32(raw[:]))
	// Unrelated Swift structs, enums, and generic templates are not candidates.
	if flags.Kind() != swift.CDKindClass || flags.IsGeneric() ||
		!flags.KindSpecific().HasResilientSuperclass() {
		return c, nil
	}
	var descriptor swift.TargetClassDescriptor
	data := make([]byte, descriptor.Size())
	available, err = f.readOptionalObjCData(addr, data)
	if !available {
		return c, err
	}
	if err := descriptor.Read(bytes.NewReader(data), addr); err != nil {
		return c, err
	}
	if !descriptor.HasObjCResilientClassStub() {
		return c, nil
	}
	return f.readObjCResilientDescriptor(addr, descriptor)
}

func objcRelativeAddress(base uint64, offset int32) (uint64, error) {
	if offset < 0 {
		delta := uint64(-int64(offset))
		if base < delta {
			return 0, fmt.Errorf("relative Objective-C address underflow")
		}
		return base - delta, nil
	}
	if base > ^uint64(0)-uint64(offset) {
		return 0, fmt.Errorf("relative Objective-C address overflow")
	}
	return base + uint64(offset), nil
}

type objcResilientPattern struct {
	dataAddr uint64
	metaAddr uint64
}

func (f *Reader) readObjCResilientClass(c swift.Class, stub uint64) (*objc.Class, error) {
	pattern, err := f.readObjCResilientPattern(&c)
	if err != nil || pattern == nil {
		return nil, err
	}
	info, err := f.GetObjCClassInfo(pattern.dataAddr)
	if err != nil {
		return nil, err
	}
	class, err := f.readObjCClassRO(info, true)
	if err != nil {
		return nil, err
	}
	class.SuperClass = c.SuperclassName()
	if class.SuperClass == "" {
		return nil, fmt.Errorf("missing resilient superclass name")
	}
	class.IsSwiftStable = true
	class.ClassPtr = stub
	class.DataVMAddr = pattern.dataAddr
	class.IsaVMAddr = pattern.metaAddr
	metaClass, err := f.readObjCResilientMetaclass(pattern.metaAddr)
	if err != nil {
		return nil, err
	}
	class.Isa = metaClass.Name
	class.ClassMethods = metaClass.InstanceMethods
	return class, nil
}

func objcResilientPatternAddress(c *swift.Class) (uint64, error) {
	if c.SingletonMetadata == nil || !c.SingletonMetadata.IncompleteMetadata.IsSet() {
		return 0, fmt.Errorf("missing resilient class metadata pattern")
	}
	ref := c.SingletonMetadata.IncompleteMetadata
	addr, err := objcRelativeAddress(ref.Address, ref.RelOff)
	if err != nil {
		return 0, err
	}
	if addr > ^uint64(0)-24 {
		return 0, fmt.Errorf("resilient class metadata pattern address overflow")
	}
	return addr, nil
}

func (f *Reader) readObjCResilientPattern(c *swift.Class) (*objcResilientPattern, error) {
	addr, err := objcResilientPatternAddress(c)
	if err != nil {
		return nil, err
	}
	var raw [24]byte
	// A static stub can refer to a pattern materialized only at runtime.
	if f.CheckFileData(addr, uint64(len(raw))) != nil {
		return nil, nil
	}
	available, err := f.readObjCResilientSuperclass(c)
	if err != nil || !available {
		return nil, err
	}
	if err := f.readObjCBytes(addr, raw[:]); err != nil {
		return nil, fmt.Errorf("read resilient class metadata pattern: %w", err)
	}
	return f.objcResilientPatternOffsets(addr, raw)
}

func (f *Reader) readObjCResilientSuperclass(c *swift.Class) (bool, error) {
	if !c.SuperclassType.IsSet() {
		return true, nil
	}
	ref := c.SuperclassType
	addr, err := objcRelativeAddress(ref.Address, ref.RelOff)
	if err != nil {
		return false, err
	}
	if f.CheckFileData(addr, 1) != nil {
		return false, nil
	}
	c.SuperClass, err = f.SymbolicMangledNameStringRef(addr)
	if err != nil {
		return false, fmt.Errorf("read resilient superclass name: %w", err)
	}
	return true, nil
}

func (f *Reader) objcResilientPatternOffsets(
	addr uint64, raw [24]byte,
) (*objcResilientPattern, error) {
	dataOffset := int32(f.ByteOrder().Uint32(raw[16:20]))
	metaOffset := int32(f.ByteOrder().Uint32(raw[20:24]))
	if dataOffset == 0 || metaOffset == 0 {
		return nil, fmt.Errorf("missing Objective-C data in resilient class metadata pattern")
	}
	dataAddr, err := objcRelativeAddress(addr+16, dataOffset)
	if err != nil {
		return nil, err
	}
	metaAddr, err := objcRelativeAddress(addr+20, metaOffset)
	if err != nil {
		return nil, err
	}
	return &objcResilientPattern{dataAddr: dataAddr, metaAddr: metaAddr}, nil
}

func (f *Reader) readObjCResilientMetaclass(addr uint64) (*objc.Class, error) {
	// Its superclass can itself be a stub, so read only the static RO data.
	if err := f.CheckFileData(addr, uint64(binary.Size(objc.ObjcClass64{}))); err != nil {
		return nil, fmt.Errorf("failed to read resilient metaclass: %w", err)
	}
	if err := f.DataReader().SeekToAddr(addr); err != nil {
		return nil, err
	}
	var meta objc.ObjcClass64
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &meta); err != nil {
		return nil, err
	}
	dataAddr := f.ConvertPointer(meta.DataVMAddrAndFastFlags) & objc.FAST_DATA_MASK64
	info, err := f.GetObjCClassInfo(dataAddr)
	if err != nil {
		return nil, err
	}
	return f.readObjCClassRO(info, true)
}

// readObjCResilientDescriptor reads only the trailers needed for class discovery.
// Swift vtable and override records are skipped with bounded counts: their
// implementations are irrelevant to the Objective-C method lists in class_ro.
func (f *Reader) readObjCResilientDescriptor(
	addr uint64, descriptor swift.TargetClassDescriptor,
) (swift.Class, error) {
	c := swift.Class{TargetClassDescriptor: descriptor}
	metadata, cursor, err := f.readObjCResilientSingleton(addr, descriptor)
	if err != nil || metadata == nil {
		return c, err
	}
	c.SingletonMetadata = metadata
	cursor, available, err := f.skipObjCResilientTables(cursor, descriptor)
	if err != nil || !available {
		return c, err
	}
	var stubInfo swift.TargetObjCResilientClassStubInfo
	data := make([]byte, stubInfo.Size())
	available, err = f.readOptionalObjCData(cursor, data)
	if !available {
		return c, err
	}
	if err := stubInfo.Read(bytes.NewReader(data), cursor); err != nil {
		return c, err
	}
	c.ObjCResilientClassStubInfo = &stubInfo
	return c, nil
}

func (f *Reader) readObjCResilientSingleton(
	addr uint64, descriptor swift.TargetClassDescriptor,
) (*swift.TargetSingletonMetadataInitialization, uint64, error) {
	if addr > ^uint64(0)-uint64(descriptor.Size())-4 {
		return nil, 0, fmt.Errorf("resilient descriptor address overflow")
	}
	if f.CheckFileData(addr, uint64(descriptor.Size())+4) != nil {
		return nil, 0, nil
	}
	cursor := addr + uint64(descriptor.Size()) + 4 // resilient superclass reference
	if !descriptor.Flags.KindSpecific().MetadataInitialization().Singleton() {
		return nil, 0, fmt.Errorf("resilient class has no singleton metadata initialization")
	}
	var metadata swift.TargetSingletonMetadataInitialization
	data := make([]byte, metadata.Size())
	available, err := f.readOptionalObjCData(cursor, data)
	if !available {
		return nil, 0, err
	}
	if err := metadata.Read(bytes.NewReader(data), cursor); err != nil {
		return nil, 0, err
	}
	if cursor > ^uint64(0)-uint64(metadata.Size()) {
		return nil, 0, fmt.Errorf("resilient descriptor address overflow")
	}
	return &metadata, cursor + uint64(metadata.Size()), nil
}

func (f *Reader) skipObjCResilientTables(
	cursor uint64, descriptor swift.TargetClassDescriptor,
) (uint64, bool, error) {
	for _, table := range []struct {
		present        bool
		header, stride uint64
	}{
		{descriptor.Flags.KindSpecific().HasVTable(), 8, 8},
		{descriptor.Flags.KindSpecific().HasOverrideTable(), 4, 12},
	} {
		if !table.present {
			continue
		}
		next, available, err := f.skipObjCResilientTable(cursor, table.header, table.stride)
		if err != nil || !available {
			return 0, false, err
		}
		cursor = next
	}
	return cursor, true, nil
}

func (f *Reader) skipObjCResilientTable(cursor, header, stride uint64) (uint64, bool, error) {
	if cursor > ^uint64(0)-header {
		return 0, false, fmt.Errorf("resilient descriptor table address overflow")
	}
	if f.CheckFileData(cursor, header) != nil {
		return 0, false, nil
	}
	var raw [4]byte
	if err := f.readObjCBytes(cursor+header-4, raw[:]); err != nil {
		return 0, false, err
	}
	count := uint64(f.ByteOrder().Uint32(raw[:]))
	if count > 1<<20 {
		return 0, false, fmt.Errorf("resilient descriptor table count too large: %d", count)
	}
	size := header + count*stride
	if cursor > ^uint64(0)-size {
		return 0, false, fmt.Errorf("resilient descriptor table address overflow")
	}
	if f.CheckFileData(cursor, size) != nil {
		return 0, false, nil
	}
	return cursor + size, true, nil
}
