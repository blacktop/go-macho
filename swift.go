package macho

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types/swift"
	fieldmd "github.com/blacktop/go-macho/types/swift/fields"
	"github.com/blacktop/go-macho/types/swift/protocols"
	stypes "github.com/blacktop/go-macho/types/swift/types"
)

const sizeOfInt32 = 4
const sizeOfInt64 = 8

// GetSwiftProtocols parses all the protocols in the __TEXT.__swift5_protos section
func (f *File) GetSwiftProtocols() ([]protocols.Protocol, error) {
	var protos []protocols.Protocol

	if sec := f.Section("__TEXT", "__swift5_protos"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		relOffsets := make([]int32, len(dat)/sizeOfInt32)

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			offset := int64(sec.Offset+uint32(idx*sizeOfInt32)) + int64(relOff)

			f.cr.Seek(offset, io.SeekStart)

			var proto protocols.Protocol
			if err := binary.Read(f.cr, f.ByteOrder, &proto.Descriptor); err != nil {
				return nil, fmt.Errorf("failed to read protocols.Descriptor: %v", err)
			}

			proto.Name, err = f.GetCStringAtOffset(offset + 8 + int64(proto.NameOffset))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}

			if proto.AssociatedTypeNamesOffset > 0 { // FIXME: this needs to be tested
				proto.AssociatedType, err = f.GetCStringAtOffset(offset + 20 + int64(proto.AssociatedTypeNamesOffset))
				if err != nil {
					return nil, fmt.Errorf("failed to read cstring: %v", err)
				}
			}

			// TODO: what if parent has parent ?
			parentOffset := offset + 4 + int64(proto.Descriptor.ParentOffset)
			f.cr.Seek(parentOffset, io.SeekStart)

			proto.Parent = new(protocols.Protocol)
			if err := binary.Read(f.cr, f.ByteOrder, &proto.Parent.Descriptor); err != nil {
				return nil, fmt.Errorf("failed to read protocols.Descriptor: %v", err)
			}

			proto.Parent.Name, err = f.GetCStringAtOffset(parentOffset + 8 + int64(proto.Parent.Descriptor.NameOffset))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}

			protos = append(protos, proto)
		}

		return protos, nil
	}

	return nil, fmt.Errorf("file does not contain a '__swift5_protos' section")
}

// GetSwiftProtocolConformances parses all the protocol conformances in the __TEXT.__swift5_proto section
func (f *File) GetSwiftProtocolConformances() ([]protocols.ConformanceDescriptor, error) {
	var protoConfDescs []protocols.ConformanceDescriptor

	if sec := f.Section("__TEXT", "__swift5_proto"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		relOffsets := make([]int32, len(dat)/sizeOfInt32)

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			offset := int64(sec.Offset+uint32(idx*sizeOfInt32)) + int64(relOff)

			f.cr.Seek(offset, io.SeekStart)

			var pcd protocols.ConformanceDescriptor
			if err := binary.Read(f.cr, f.ByteOrder, &pcd.CDType); err != nil {
				return nil, fmt.Errorf("failed to read swift ProtocolDescriptor: %v", err)
			}

			var ptr uint64
			if (pcd.ProtocolDescriptorOffset & 1) == 1 {
				pcd.ProtocolDescriptorOffset = pcd.ProtocolDescriptorOffset &^ 1
				f.cr.Seek(offset+int64(pcd.ProtocolDescriptorOffset), io.SeekStart)
				if err := binary.Read(f.cr, f.ByteOrder, &ptr); err != nil {
					return nil, fmt.Errorf("failed to read protocol name offset: %v", err)
				}
			} else {
				ptr = uint64(offset + int64(pcd.ProtocolDescriptorOffset))
			}

			if fixupchains.DcpArm64eIsBind(ptr) {
				pcd.Protocol, err = f.GetBindName(ptr)
				if err != nil {
					return nil, fmt.Errorf("failed to read protocol name: %v", err)
				}
			} else {
				pcd.Protocol, err = f.GetCString(f.SlidePointer(ptr))
				if err != nil {
					return nil, fmt.Errorf("failed to read protocol name: %v", err)
				}
			}

			switch pcd.Flags.GetTypeReferenceKind() {
			case protocols.DirectTypeDescriptor:
			case protocols.IndirectTypeDescriptor:
			case protocols.DirectObjCClassName:
			case protocols.IndirectObjCClass:
			}

			protoConfDescs = append(protoConfDescs, pcd)
		}

		return protoConfDescs, nil
	}
	return nil, fmt.Errorf("file does not contain a '__swift5_proto' section")
}

// GetSwiftTypes parses all the types in the __TEXT.__swift5_types section
func (f *File) GetSwiftTypes() ([]*stypes.TypeDescriptor, error) {
	var types []*stypes.TypeDescriptor

	if sec := f.Section("__TEXT", "__swift5_types"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		relOffsets := make([]int32, len(dat)/sizeOfInt32)
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			offset := int64(sec.Offset+uint32(idx*sizeOfInt32)) + int64(relOff)

			f.cr.Seek(offset, io.SeekStart)

			var tDesc stypes.TargetContextDescriptor
			if err := binary.Read(f.cr, f.ByteOrder, &tDesc); err != nil {
				return nil, fmt.Errorf("failed to read stypes.TypeDescriptor: %v", err)
			}

			f.cr.Seek(-int64(binary.Size(tDesc)), io.SeekCurrent) // rewind

			var typ stypes.TypeDescriptor

			switch tDesc.Flags.Kind() {
			case stypes.Class:
				var cD stypes.TargetClassDescriptor
				if err := binary.Read(f.cr, f.ByteOrder, &cD); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", cD, err)
				}
				typ.Type = &cD
			case stypes.Struct:
				var sD stypes.StructDescriptor
				if err := binary.Read(f.cr, f.ByteOrder, &sD); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", sD, err)
				}
				typ.Type = &sD
			case stypes.Enum:
				var eD stypes.EnumDescriptor
				if err := binary.Read(f.cr, f.ByteOrder, &eD); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", eD, err)
				}
				typ.Type = &eD
			}

			typ.Parent, err = f.GetCStringAtOffset(offset + int64(tDesc.Parent))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}

			typ.Name, err = f.GetCStringAtOffset(offset + 8 + int64(tDesc.Name))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}

			if tDesc.FieldDescriptor != 0 {
				typ.Field, err = f.readField(offset + 16 + int64(tDesc.FieldDescriptor))
				if err != nil {
					return nil, fmt.Errorf("failed to read swift field: %v", err)
				}
			}

			types = append(types, &typ)
		}

		return types, nil
	}

	return nil, fmt.Errorf("file does not contain a '__swift5_types' section")
}

func (f *File) readField(offset int64) (*fieldmd.Field, error) {
	var field fieldmd.Field

	currOffset, err := f.cr.Seek(offset, io.SeekStart)
	if err != nil {
		return nil, err
	}

	if err := binary.Read(f.cr, f.ByteOrder, &field.Descriptor.Header); err != nil {
		return nil, fmt.Errorf("failed to read swift.Header: %v", err)
	}

	field.Kind = field.Descriptor.Kind.String()

	field.TypeName, _, err = f.getMangledTypeAtOffset(currOffset + int64(field.Descriptor.Header.MangledTypeName))
	if err != nil {
		return nil, fmt.Errorf("failed to read swift field MangledTypeName at %#x: %v", currOffset+int64(field.Descriptor.Header.MangledTypeName), err)
	}

	if field.Descriptor.Header.Superclass == 0 {
		field.SuperClass = swift.MANGLING_MODULE_OBJC
	} else {
		field.SuperClass, err = f.GetCStringAtOffset(currOffset + sizeOfInt32 + int64(field.Descriptor.Header.Superclass))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	}

	currOffset, err = f.cr.Seek(offset+int64(binary.Size(fieldmd.Header{})), io.SeekStart)
	if err != nil {
		return nil, err
	}

	field.Descriptor.FieldRecords = make([]fieldmd.FieldRecordType, field.Descriptor.Header.NumFields)
	if err := binary.Read(f.cr, f.ByteOrder, &field.Descriptor.FieldRecords); err != nil {
		return nil, fmt.Errorf("failed to read swift field records: %v", err)
	}

	for idx, record := range field.Descriptor.FieldRecords {
		rec := fieldmd.FieldRecord{
			Flags: record.Flags.String(),
		}

		currOffset += int64(idx * int(field.Descriptor.FieldRecordSize))

		if record.MangledTypeName != 0 {
			rec.MangledTypeName, _, err = f.getMangledTypeAtOffset(currOffset + 4 + int64(record.MangledTypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read swift field record MangledTypeName at %#x; %v", currOffset+4+int64(record.MangledTypeName), err)
			}
		}

		rec.Name, err = f.GetCStringAtOffset(currOffset + 8 + int64(record.FieldName))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}

		field.Records = append(field.Records, rec)
	}

	return &field, nil
}

// GetSwiftFields parses all the fields in the __TEXT.__swift5_fieldmd section
func (f *File) GetSwiftFields() ([]fieldmd.Field, error) {
	var fields []fieldmd.Field

	if sec := f.Section("__TEXT", "__swift5_fieldmd"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			fileOffset, _ := r.Seek(0, io.SeekCurrent)
			field := fieldmd.Field{Offset: fileOffset + int64(sec.Offset)}

			err = binary.Read(r, f.ByteOrder, &field.Descriptor.Header)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read swift.Header: %v", err)
			}

			field.Kind = field.Descriptor.Header.Kind.String()

			field.Descriptor.FieldRecords = make([]fieldmd.FieldRecordType, field.Descriptor.Header.NumFields)
			if err := binary.Read(r, f.ByteOrder, &field.Descriptor.FieldRecords); err != nil {
				return nil, fmt.Errorf("failed to read []fieldmd.RecordT: %v", err)
			}

			fields = append(fields, field)
		}

		// parse fields
		for idx, fd := range fields {
			typeName, _, err := f.getMangledTypeAtOffset(fd.Offset + int64(fd.Descriptor.MangledTypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read MangledTypeName: %v", err)
			}
			fields[idx].TypeName = typeName
		}

		return fields, nil
	}

	return nil, fmt.Errorf("file does not contain a __swift5_fieldmd section")
}

// GetSwiftAssociatedTypes parses all the associated types in the __TEXT.__swift5_assocty section
func (f *File) GetSwiftAssociatedTypes() ([]swift.AssociatedTypeDescriptor, error) {
	var accocTypes []swift.AssociatedTypeDescriptor

	if sec := f.Section("__TEXT", "__swift5_assocty"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			currentOffset, _ := r.Seek(0, io.SeekCurrent)

			var aType swift.AssociatedTypeDescriptor
			err := binary.Read(r, f.ByteOrder, &aType.ATDHeader)

			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read swift AssociatedTypeDescriptor header: %v", err)
			}

			aType.Address = sec.Addr + uint64(currentOffset)

			off, err := f.GetOffset(aType.Address)
			if err != nil {
				return nil, fmt.Errorf("failed to get offset for associated type at addr %#x: %v", aType.Address, err)
			}

			// AssociatedTypeDescriptor.ConformingTypeName
			coff, symbolic, err := f.makeSymbolicMangledNameStringRef(int64(off) + int64(aType.ConformingTypeNameOffset))
			if err != nil {
				return nil, fmt.Errorf("failed to read conforming type for associated type at addr %#x: %v", aType.Address, err)
			}

			if symbolic {
				aType.ConformingTypeAddr, err = f.GetVMAddress(uint64(coff))
				if err != nil {
					return nil, fmt.Errorf("failed to get vmaddr for associated types conforming type: %v", err)
				}
			} else {
				aType.ConformingTypeAddr, err = f.GetVMAddress(uint64(coff))
				if err != nil {
					return nil, fmt.Errorf("failed to get vmaddr for associated types conforming type: %v", err)
				}
				aType.ConformingTypeName, err = f.GetCString(aType.ConformingTypeAddr)
				if err != nil {
					return nil, fmt.Errorf("failed to read associated type substituted type name: %v", err)
				}
			}
			// AssociatedTypeDescriptor.ProtocolTypeName
			addr := uint64(int64(aType.Address) + int64(aType.ProtocolTypeNameOffset) + sizeOfInt32)
			aType.ProtocolTypeName, err = f.GetCString(addr)
			if err != nil {
				return nil, fmt.Errorf("failed to read swift assocated type protocol type name at addr %#x: %v", addr, err)
			}

			// AssociatedTypeRecord
			aType.AssociatedTypeRecords = make([]swift.AssociatedTypeRecord, aType.ATDHeader.NumAssociatedTypes)
			for i := uint32(0); i < aType.ATDHeader.NumAssociatedTypes; i++ {
				if err := binary.Read(r, f.ByteOrder, &aType.AssociatedTypeRecords[i].ATRecordType); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", aType.AssociatedTypeRecords[i].ATRecordType, err)
				}
				// AssociatedTypeRecord.Name
				addr := int64(aType.Address) + int64(binary.Size(aType.ATDHeader)) + int64(aType.AssociatedTypeRecords[i].NameOffset)
				aType.AssociatedTypeRecords[i].Name, err = f.GetCString(uint64(addr))
				if err != nil {
					return nil, fmt.Errorf("failed to read associated type record name: %v", err)
				}
				// AssociatedTypeRecord.SubstitutedTypeName
				symMangOff := int64(off) + int64(binary.Size(aType.ATDHeader)) + int64(aType.AssociatedTypeRecords[i].SubstitutedTypeNameOffset) + sizeOfInt32
				coff, symbolic, err := f.makeSymbolicMangledNameStringRef(symMangOff)
				if err != nil {
					return nil, fmt.Errorf("failed to read associated type substituted type symbolic ref at offset %#x: %v", symMangOff, err)
				}
				if symbolic {
					aType.AssociatedTypeRecords[i].SubstitutedTypeAddr, err = f.GetVMAddress(uint64(coff))
					if err != nil {
						return nil, fmt.Errorf("failed to get vmaddr for associated type record substituted type: %v", err)
					}
				} else {
					aType.AssociatedTypeRecords[i].SubstitutedTypeAddr, err = f.GetVMAddress(uint64(coff))
					if err != nil {
						return nil, fmt.Errorf("failed to get vmaddr for associated type record substituted type: %v", err)
					}
					aType.AssociatedTypeRecords[i].SubstitutedTypeName, err = f.GetCString(aType.AssociatedTypeRecords[i].SubstitutedTypeAddr)
					if err != nil {
						return nil, fmt.Errorf("failed to read associated type record substituted type name: %v", err)
					}
				}
			}

			accocTypes = append(accocTypes, aType)
		}

		return accocTypes, nil
	}
	return nil, fmt.Errorf("file does not contain a '__swift5_assocty' section")
}

// ref: https://github.com/apple/swift/blob/1a7146fb04665e2434d02bada06e6296f966770b/lib/Demangling/Demangler.cpp#L155
// ref: https://github.com/apple/swift/blob/main/docs/ABI/Mangling.rst#symbolic-references
func (f *File) makeSymbolicMangledNameStringRef(offset int64) (int64, bool, error) {

	controlData := make([]byte, 9)
	f.cr.ReadAt(controlData, offset)

	if controlData[0] >= 0x01 && controlData[0] <= 0x17 {
		var reference int32
		if err := binary.Read(bytes.NewReader(controlData[1:]), f.ByteOrder, &reference); err != nil {
			return 0, false, fmt.Errorf("failed to read swift symbolic reference: %v", err)
		}
		return offset + 1 + int64(reference), true, nil
	} else if controlData[0] >= 0x18 && controlData[0] <= 0x1f {
		var reference uint64
		if err := binary.Read(bytes.NewReader(controlData[1:]), f.ByteOrder, &reference); err != nil {
			return 0, false, fmt.Errorf("failed to read swift symbolic reference: %v", err)
		}
		return offset + 1 + int64(reference), true, nil
	} else {
		return offset, false, nil
	}
}

// GetSwiftBuiltinTypes parses all the built-in types in the __TEXT.__swift5_builtin section
func (f *File) GetSwiftBuiltinTypes() ([]swift.BuiltinType, error) {
	var builtins []swift.BuiltinType

	if sec := f.Section("__TEXT", "__swift5_builtin"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		builtInTypes := make([]swift.BuiltinTypeDescriptor, int(sec.Size)/binary.Size(swift.BuiltinTypeDescriptor{}))

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &builtInTypes); err != nil {
			return nil, fmt.Errorf("failed to read []swift.BuiltinTypeDescriptor: %v", err)
		}

		for idx, bType := range builtInTypes {
			currOffset := int64(sec.Offset) + int64(idx*binary.Size(swift.BuiltinTypeDescriptor{}))
			name, _, err := f.getMangledTypeAtOffset(currOffset + int64(bType.TypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read record.MangledTypeName; %v", err)
			}

			builtins = append(builtins, swift.BuiltinType{
				Name:                name,
				Size:                bType.Size,
				Alignment:           bType.AlignmentAndFlags.Alignment(),
				BitwiseTakable:      bType.AlignmentAndFlags.IsBitwiseTakable(),
				Stride:              bType.Stride,
				NumExtraInhabitants: bType.NumExtraInhabitants,
			})
		}

		return builtins, nil
	}

	return nil, fmt.Errorf("file does not contain a __swift5_builtin section")
}

// GetSwiftClosures parses all the closure context objects in the __TEXT.__swift5_capture section
func (f *File) GetSwiftClosures() ([]swift.CaptureDescriptor, error) {
	var closures []swift.CaptureDescriptor

	if sec := f.Section("__TEXT", "__swift5_capture"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			var capture swift.CaptureDescriptor
			currOffset, _ := r.Seek(0, io.SeekCurrent)
			currOffset += int64(sec.Offset)

			err := binary.Read(r, f.ByteOrder, &capture.CaptureDescriptorHeader)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read swift %T: %v", capture.CaptureDescriptorHeader, err)
			}

			currOffset += int64(binary.Size(capture.CaptureDescriptorHeader))

			if capture.CaptureDescriptorHeader.NumCaptureTypes > 0 {
				capture.CaptureTypeRecords = make([]swift.CaptureTypeRecord, capture.CaptureDescriptorHeader.NumCaptureTypes)
				if err := binary.Read(r, f.ByteOrder, &capture.CaptureTypeRecords); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", capture.CaptureTypeRecords, err)
				}
				for idx, capRecord := range capture.CaptureTypeRecords {
					currOffset += int64(idx * binary.Size(swift.CaptureTypeRecord{}))
					name, _, err := f.getMangledTypeAtOffset(currOffset + int64(capRecord.MangledTypeName))
					if err != nil {
						return nil, fmt.Errorf("failed to read mangled type name at offset %#x: %v", currOffset+int64(capRecord.MangledTypeName), err)
					}
					fmt.Println(name)
				}
			}

			closures = append(closures, capture)
		}

		return closures, nil
	}

	return nil, fmt.Errorf("file does not contain a __swift5_capture section")
}

// getMangledTypeAtOffset reads a mangled type at a given offset in the MachO FIXME: this has a bug
func (f *File) getMangledTypeAtOffset(offset int64) (string, *stypes.TargetContextDescriptor, error) {

	if _, err := f.cr.Seek(offset, io.SeekStart); err != nil {
		return "", nil, fmt.Errorf("failed to Seek: %v", err)
	}

	var refType uint8
	if err := binary.Read(f.cr, f.ByteOrder, &refType); err != nil {
		return "", nil, fmt.Errorf("failed to read possible symbolic reference type at offset %#x, %v", offset, err)
	}

	if refType >= 0x01 && refType <= 0x17 {

		var t32 int32
		if err := binary.Read(f.cr, f.ByteOrder, &t32); err != nil {
			return "", nil, fmt.Errorf("failed to read 32bit symbolic ref: %v", err)
		}

		switch refType {
		case 1:
			typeDescOffset := offset + int64(t32) + 1
			f.cr.Seek(typeDescOffset, io.SeekStart)
			var tDesc stypes.TargetContextDescriptor
			if err := binary.Read(f.cr, f.ByteOrder, &tDesc); err != nil {
				return "", nil, fmt.Errorf("failed to read stypes.TypeDescriptor: %v", err)
			}
			parentDescOffset := typeDescOffset + sizeOfInt32 + int64(tDesc.Parent)
			f.cr.Seek(parentDescOffset, io.SeekStart)
			var parentDesc stypes.TargetContextDescriptor
			if err := binary.Read(f.cr, f.ByteOrder, &parentDesc); err != nil {
				return "", nil, fmt.Errorf("failed to read stypes.TypeDescriptor: %v", err)
			}
			fmt.Println("parent:", parentDesc)
			parent, err := f.GetCStringAtOffset(parentDescOffset + 2*sizeOfInt32 + int64(parentDesc.Name))
			if err != nil {
				return "", nil, fmt.Errorf("failed to read cstring: %v", err)
			}
			if parentDesc.Parent != 0 {
				fmt.Printf("%#x\n", parentDescOffset+sizeOfInt32+int64(parentDesc.Parent))
			}
			name, err := f.GetCStringAtOffset(typeDescOffset + 2*sizeOfInt32 + int64(tDesc.Name))
			if err != nil {
				return "", nil, fmt.Errorf("failed to read cstring: %v", err)
			}
			fmt.Println("name:", parent, name, tDesc.Flags)
			return parent + "." + name, &tDesc, nil
		case 2:
			f.cr.Seek(offset+int64(t32)+1, io.SeekStart)
			var context uint64
			if err := binary.Read(f.cr, f.ByteOrder, &context); err != nil {
				return "", nil, fmt.Errorf("failed to read 32bit symbolic ref: %v", err)
			}
			// Check if context pointer is a dyld chain fixup REBASE
			if fixupchains.DcpArm64eIsRebase(context) {
				off, err := f.GetOffset(f.vma.Convert(context))
				if err != nil {
					return "", nil, fmt.Errorf("failed to GetOffset: %v", err)
				}
				f.cr.Seek(int64(off), io.SeekStart)

				var tDesc stypes.TargetContextDescriptor
				if err := binary.Read(f.cr, f.ByteOrder, &tDesc); err != nil {
					return "", nil, fmt.Errorf("failed to read stypes.TypeDescriptor: %v", err)
				}

				name, err := f.GetCStringAtOffset(int64(off) + 8 + int64(tDesc.Name))
				if err != nil {
					return "", nil, fmt.Errorf("failed to read cstring: %v", err)
				}
				fmt.Println("name:", name, tDesc.Flags)
				return name, &tDesc, nil
			}
			// context pointer is a dyld chain fixup BIND
			dcf, err := f.DyldChainedFixups()
			if err != nil {
				return "", nil, fmt.Errorf("failed to get DyldChainedFixups: %v", err)
			}
			name := dcf.Imports[fixupchains.DyldChainedPtrArm64eBind{Pointer: context}.Ordinal()].Name
			return name, nil, nil
		default:
			return "", nil, fmt.Errorf("unsupported symbolic REF: %X, %#x", refType, offset+int64(t32))
		}

	} else if refType >= byte(0x18) && refType <= byte(0x1F) { // TODO: finish support for these types
		int64Bytes := make([]byte, 8)
		if _, err := f.cr.Read(int64Bytes); err != nil {
			return "", nil, fmt.Errorf("unsupported symbolic REF: %X, %#x", refType, offset+int64(binary.LittleEndian.Uint64(int64Bytes)))
		}
	} else { // regular string mangled type
		// revert the peek byte read
		if _, err := f.cr.Seek(-1, io.SeekCurrent); err != nil {
			return "", nil, fmt.Errorf("failed to Seek: %v", err)
		}
		s, err := bufio.NewReader(f.cr).ReadString('\x00')
		if err != nil {
			return "", nil, fmt.Errorf("failed to ReadBytes at offset %#x, %v", offset, err)
		}
		s = strings.Trim(s, "\x00")
		if len(s) == 0 { // TODO this shouldn't happen
			return "", nil, fmt.Errorf("failed to get read a string at offset %#x, %v", offset, err)
		}
		return "_$s" + strings.Trim(s, "\x00"), nil, nil // TODO: fix this append to be correct for all cases
	}

	return "", nil, fmt.Errorf("type data not found")
}

func (f *File) GetSwiftReflectionStrings() ([]string, error) {
	var reflStrings []string
	if sec := f.Section("__TEXT", "__swift5_reflstr"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
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

			s = strings.TrimSpace(strings.Trim(s, "\x00"))

			if len(s) > 0 {
				reflStrings = append(reflStrings, s)
			}
		}

		return reflStrings, nil
	}

	return nil, fmt.Errorf("failed to find '__swift5_reflstr' section")
}

func (f *File) GetSwiftEntry() (uint64, error) {
	if sec := f.Section("__TEXT", "__swift5_entry"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return 0, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return 0, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		var swiftEntry int32
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &swiftEntry); err != nil {
			return 0, fmt.Errorf("failed to read __swift5_entry data: %v", err)
		}

		return sec.Addr + uint64(swiftEntry), nil
	}

	return 0, fmt.Errorf("failed to find '__swift5_entry' section")
}
