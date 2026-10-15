package objcreader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types/objc"
)

func (f *Reader) readObjcProtocolListPointers(vmaddr uint64) ([]uint64, error) {
	if err := f.CheckFileData(vmaddr, 8); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t: %w", err)
	}

	if err := f.DataReader().SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc protocol list vmaddr: %#x; %v", vmaddr, err)
	}

	var protList objc.ProtocolList
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &protList.Count); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t count: %v", err)
	}
	if err := f.checkObjCListData(vmaddr, 8, protList.Count, 8); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t: %w", err)
	}

	protList.Protocols = make([]uint64, protList.Count)
	if err := binary.Read(f.DataReader(), f.ByteOrder(), &protList.Protocols); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t prots: %v", err)
	}
	return protList.Protocols, nil
}

func (f *Reader) parseObjcProtocolList(vmaddr uint64) ([]objc.Protocol, error) {
	ptrs, err := f.readObjcProtocolListPointers(vmaddr)
	if err != nil {
		return nil, err
	}
	var protocols []objc.Protocol
	for _, protPtr := range ptrs {
		protAddr := f.ConvertPointer(protPtr)
		prot, err := f.getObjcProtocol(protAddr)
		if err != nil {
			return nil, err
		}
		if prot != nil {
			protocols = append(protocols, *prot)
		}
	}

	return protocols, nil
}

const objcProtocolPrefixSize = 72

func (f *Reader) readObjcProtocolRecord(vmaddr uint64) (*objc.ProtocolT, error) {
	if !f.AddressResolvable(vmaddr) {
		return nil, nil
	}

	// Older protocol records end before the optional pointer fields.
	var raw [96]byte
	if err := f.readObjCData(vmaddr, raw[:objcProtocolPrefixSize]); err != nil {
		return nil, fmt.Errorf("failed to read protocol_t: %w", err)
	}
	size := f.ByteOrder().Uint32(raw[64:68])
	readSize := objcProtocolPrefixSize
	for _, end := range []uint32{80, 88, 96} {
		if size >= end {
			readSize = int(end)
		}
	}
	if err := f.readObjcProtocolTail(vmaddr, raw[:readSize]); err != nil {
		return nil, fmt.Errorf("failed to read protocol_t: %w", err)
	}
	var protoPtr objc.ProtocolT
	if err := binary.Read(bytes.NewReader(raw[:]), f.ByteOrder(), &protoPtr); err != nil {
		return nil, fmt.Errorf("failed to read protocol_t: %v", err)
	}
	return &protoPtr, nil
}

func (f *Reader) readObjcProtocolTail(vmaddr uint64, raw []byte) error {
	if len(raw) <= objcProtocolPrefixSize {
		return nil
	}
	if err := f.CheckFileData(vmaddr, uint64(len(raw))); err != nil {
		return err
	}
	return f.readObjCBytes(vmaddr+objcProtocolPrefixSize, raw[objcProtocolPrefixSize:])
}

func (f *Reader) getObjcProtocol(vmaddr uint64) (*objc.Protocol, error) {
	record, err := f.readObjcProtocolRecord(vmaddr)
	if err != nil || record == nil {
		return nil, err
	}
	proto := &objc.Protocol{Ptr: vmaddr, ProtocolT: *record}
	if err := f.readObjcProtocolBase(proto); err != nil {
		return nil, err
	}
	if err := f.readObjcProtocolMethods(proto); err != nil {
		return nil, err
	}
	proto.InstanceProperties, err = f.readObjcProtocolProperties(&proto.InstancePropertiesVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read instance property vmaddr: %v", err)
	}
	if err := f.readObjcProtocolNames(proto); err != nil {
		return nil, err
	}
	// The record reader leaves class properties zero unless Size includes them.
	proto.ClassProperties, err = f.readObjcProtocolProperties(&proto.ClassPropertiesVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read class property vmaddr: %v", err)
	}
	return proto, nil
}

func (f *Reader) readObjcProtocolBase(proto *objc.Protocol) error {
	var err error
	if proto.NameVMAddr > 0 {
		proto.NameVMAddr = f.ConvertPointer(proto.NameVMAddr)
		proto.Name, err = f.GetCString(proto.NameVMAddr)
		if err != nil {
			return fmt.Errorf("failed to read cstring: %v", err)
		}
	}
	if proto.IsaVMAddr > 0 {
		proto.IsaVMAddr = f.ConvertPointer(proto.IsaVMAddr)
		if c, ok := f.GetObjC(proto.IsaVMAddr); ok {
			proto.Isa = c.(*objc.Class)
		}
	}
	if proto.ProtocolsVMAddr > 0 {
		proto.ProtocolsVMAddr = f.ConvertPointer(proto.ProtocolsVMAddr)
		proto.Prots, err = f.parseObjcProtocolList(proto.ProtocolsVMAddr)
		if err != nil {
			return fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}
	return nil
}

func (f *Reader) readObjcProtocolMethods(proto *objc.Protocol) error {
	for _, list := range []struct {
		addr    *uint64
		methods *[]objc.Method
		name    string
	}{
		{&proto.InstanceMethodsVMAddr, &proto.InstanceMethods, "instance"},
		{&proto.OptionalInstanceMethodsVMAddr, &proto.OptionalInstanceMethods, "optional instance"},
		{&proto.ClassMethodsVMAddr, &proto.ClassMethods, "class"},
		{&proto.OptionalClassMethodsVMAddr, &proto.OptionalClassMethods, "optional class"},
	} {
		if *list.addr == 0 {
			continue
		}
		*list.addr = f.ConvertPointer(*list.addr)
		methods, err := f.GetObjCMethods(*list.addr)
		if err != nil {
			return fmt.Errorf("failed to read %s method vmaddr: %v", list.name, err)
		}
		*list.methods = methods
	}
	return nil
}

func (f *Reader) readObjcProtocolProperties(addr *uint64) ([]objc.Property, error) {
	if *addr == 0 {
		return nil, nil
	}
	*addr = f.ConvertPointer(*addr)
	return f.getObjCPropertiesWithSwift(*addr, false)
}

func (f *Reader) readObjcProtocolNames(proto *objc.Protocol) error {
	var err error
	if proto.HasExtendedMethodTypes() && proto.ExtendedMethodTypesVMAddr > 0 {
		proto.ExtendedMethodTypesVMAddr = f.ConvertPointer(proto.ExtendedMethodTypesVMAddr)
		var raw [8]byte
		if err := f.readObjCData(proto.ExtendedMethodTypesVMAddr, raw[:]); err != nil {
			return fmt.Errorf("failed to read ExtendedMethodTypesVMAddr: %w", err)
		}
		addr := f.ConvertPointer(f.ByteOrder().Uint64(raw[:]))
		proto.ExtendedMethodTypes, err = f.GetCString(addr)
		if err != nil {
			return fmt.Errorf("failed to read proto extended method types cstring: %v", err)
		}
	}
	if proto.HasDemangledName() && proto.DemangledNameVMAddr > 0 {
		proto.DemangledNameVMAddr = f.ConvertPointer(proto.DemangledNameVMAddr)
		proto.DemangledName, err = f.GetCString(proto.DemangledNameVMAddr)
		if err != nil {
			return fmt.Errorf("failed to read proto demangled name cstring: %v", err)
		}
	}
	return nil
}

func (f *Reader) checkObjCListData(addr, header, count, stride uint64) error {
	if count > 1<<20 || stride == 0 || count > (^uint64(0)-header)/stride {
		return fmt.Errorf("Objective-C metadata list count too large: %d", count)
	}
	return f.CheckFileData(addr, header+count*stride)
}

// GetObjCProtocols returns locally readable Objective-C protocol definitions.
// Unavailable external references are skipped; truncated records return an error.
func (f *Reader) GetObjCProtocols() ([]objc.Protocol, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCProtocols"); err != nil {
		return nil, err
	}

	var protocols []objc.Protocol

	for _, s := range f.SegmentNames() {
		if strings.HasPrefix(s, "__DATA") {
			if sec := f.Section(s, "__objc_protolist"); sec != nil {
				ptrs, err := f.readSectionPointers(sec)
				if err != nil {
					return nil, err
				}
				for _, ptr := range ptrs {
					protAddr := f.ConvertPointer(ptr)
					proto, err := f.getObjcProtocol(protAddr)
					if err != nil {
						return nil, fmt.Errorf(
							"failed to read protocol at pointer %#x (converted %#x); %v",
							ptr, protAddr, err)
					}
					if proto != nil {
						protocols = append(protocols, *proto)
					}
				}
			}
		}
	}
	return protocols, nil
}
