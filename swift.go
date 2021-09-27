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
func (f *File) GetSwiftProtocols() (*[]protocols.Protocol, error) {
	var protos []protocols.Protocol

	if sec := f.Section("__TEXT", "__swift5_protos"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_protos: %v", err)
		}

		relOffsets := make([]int32, len(dat)/sizeOfInt32)

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			offset := int64(sec.Offset+uint32(idx*sizeOfInt32)) + int64(relOff)

			f.sr.Seek(offset, io.SeekStart)

			var proto protocols.Protocol
			if err := binary.Read(f.sr, f.ByteOrder, &proto.Descriptor); err != nil {
				return nil, fmt.Errorf("failed to read protocols.Descriptor: %v", err)
			}

			proto.Name, err = f.GetCStringAtOffset(offset + 8 + int64(proto.Descriptor.Name))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}

			parentOffset := offset + 4 + int64(proto.Descriptor.Parent)
			f.sr.Seek(parentOffset, io.SeekStart)

			proto.Parent = new(protocols.Protocol)
			if err := binary.Read(f.sr, f.ByteOrder, &proto.Parent.Descriptor); err != nil {
				return nil, fmt.Errorf("failed to read protocols.Descriptor: %v", err)
			}

			proto.Parent.Name, err = f.GetCStringAtOffset(parentOffset + 8 + int64(proto.Parent.Descriptor.Name))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}

			protos = append(protos, proto)
		}

		return &protos, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_protos section")
}

// GetSwiftProtocolConformances parses all the protocol conformances in the __TEXT.__swift5_proto section
func (f *File) GetSwiftProtocolConformances() (*[]protocols.ConformanceDescriptor, error) {
	var protoConfDescs []protocols.ConformanceDescriptor

	if sec := f.Section("__TEXT", "__swift5_proto"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_protos: %v", err)
		}

		relOffsets := make([]int32, len(dat)/sizeOfInt32)

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			offset := int64(sec.Offset+uint32(idx*sizeOfInt32)) + int64(relOff)

			f.sr.Seek(offset, io.SeekStart)

			var pcd protocols.ConformanceDescriptor
			if err := binary.Read(f.sr, f.ByteOrder, &pcd); err != nil {
				return nil, fmt.Errorf("failed to read swift.ProtocolDescriptor: %v", err)
			}

			protoConfDescs = append(protoConfDescs, pcd)
		}

		return &protoConfDescs, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_protos section")
}

// GetSwiftTypes parses all the types in the __TEXT.__swift5_types section
func (f *File) GetSwiftTypes() (*[]stypes.TypeDescriptor, error) {
	var classes []stypes.TypeDescriptor

	if sec := f.Section("__TEXT", "__swift5_types"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_types: %v", err)
		}

		relOffsets := make([]int32, len(dat)/sizeOfInt32)
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			offset := int64(sec.Offset+uint32(idx*sizeOfInt32)) + int64(relOff)

			f.sr.Seek(offset, io.SeekStart)

			var tDesc stypes.TypeDescriptor
			if err := binary.Read(f.sr, f.ByteOrder, &tDesc); err != nil {
				return nil, fmt.Errorf("failed to read stypes.TypeDescriptor: %v", err)
			}

			fmt.Println(tDesc.Flags)

			if tDesc.Flags.Kind() == stypes.Struct {
				var sD stypes.StructDescriptor
				sD.TypeDescriptor = tDesc
				if err := binary.Read(f.sr, f.ByteOrder, &sD.NumFields); err != nil {
					return nil, fmt.Errorf("failed to read types.StructDescriptor: %v", err)
				}
				if err := binary.Read(f.sr, f.ByteOrder, &sD.FieldOffsetVectorOffset); err != nil {
					return nil, fmt.Errorf("failed to read types.StructDescriptor: %v", err)
				}
				fmt.Printf("%#v\n", sD)
			}
			parent, err := f.GetCStringAtOffset(offset + int64(tDesc.Parent))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}
			fmt.Printf("parent: %s %v\n", parent, []byte(parent))

			name, err := f.GetCStringAtOffset(offset + 8 + int64(tDesc.Name))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}
			fmt.Println(name)
			if tDesc.FieldDescriptor != 0 {
				field, err := f.readField(offset + 16 + int64(tDesc.FieldDescriptor))
				if err != nil {
					return nil, fmt.Errorf("failed to read swift field: %v", err)
				}
				fmt.Println(field)
			}
			classes = append(classes, tDesc)
		}

		return &classes, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_types section")
}

func (f *File) readField(offset int64) (*fieldmd.Field, error) {
	var field fieldmd.Field
	var err error

	currOffset, err := f.sr.Seek(offset, io.SeekStart)
	if err != nil {
		return nil, err
	}

	if err := binary.Read(f.sr, f.ByteOrder, &field.Descriptor.Header); err != nil {
		return nil, fmt.Errorf("failed to read swift.Header: %v", err)
	}

	field.Kind = field.Descriptor.Kind.String()

	field.TypeName, _, err = f.GetMangledTypeAtOffset(currOffset + int64(field.Descriptor.Header.MangledTypeName))
	if err != nil {
		return nil, fmt.Errorf("failed to read fieldmd.MangledTypeName: %v", err)
	}

	if field.Descriptor.Header.Superclass == 0 {
		field.SuperClass = swift.MANGLING_MODULE_OBJC
	} else {
		field.SuperClass, err = f.GetCStringAtOffset(currOffset + sizeOfInt32 + int64(field.Descriptor.Header.Superclass))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	}

	currOffset, err = f.sr.Seek(offset+int64(binary.Size(fieldmd.Header{})), io.SeekStart)
	if err != nil {
		return nil, err
	}

	field.Descriptor.FieldRecords = make([]fieldmd.RecordT, field.Descriptor.Header.NumFields)
	if err := binary.Read(f.sr, f.ByteOrder, &field.Descriptor.FieldRecords); err != nil {
		return nil, fmt.Errorf("failed to read []fieldmd.RecordT: %v", err)
	}

	for idx, record := range field.Descriptor.FieldRecords {
		rec := fieldmd.Record{
			Flags: record.Flags.String(),
		}

		currOffset += int64(idx * int(field.Descriptor.FieldRecordSize))

		if record.MangledTypeName != 0 {
			rec.MangledTypeName, _, err = f.GetMangledTypeAtOffset(currOffset + 4 + int64(record.MangledTypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read fieldmd.Record.MangledTypeName; %v", err)
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
func (f *File) GetSwiftFields() (*[]fieldmd.Field, error) {
	var fields []fieldmd.Field

	if sec := f.Section("__TEXT", "__swift5_fieldmd"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_fieldmd: %v", err)
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

			field.Descriptor.FieldRecords = make([]fieldmd.RecordT, field.Descriptor.Header.NumFields)
			if err := binary.Read(r, f.ByteOrder, &field.Descriptor.FieldRecords); err != nil {
				return nil, fmt.Errorf("failed to read []fieldmd.RecordT: %v", err)
			}

			fields = append(fields, field)
		}

		// parse fields
		for idx, fd := range fields {
			typeName, _, err := f.GetMangledTypeAtOffset(fd.Offset + int64(fd.Descriptor.MangledTypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read MangledTypeName: %v", err)
			}
			fields[idx].TypeName = typeName
		}

		return &fields, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_fieldmd section")
}

// GetSwiftAssociatedTypes parses all the associated types in the __TEXT.__swift5_assocty section
func (f *File) GetSwiftAssociatedTypes() (*[]swift.AssociatedTypeDescriptor, error) {
	var accocTypes []swift.AssociatedTypeDescriptor

	if sec := f.Section("__TEXT", "__swift5_assocty"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_assocty: %v", err)
		}

		r := bytes.NewReader(dat)

		for {
			currOffset, _ := r.Seek(0, io.SeekCurrent)
			currOffset += int64(sec.Offset)

			var aType swift.AssociatedTypeDescriptor
			err := binary.Read(r, f.ByteOrder, &aType.AssociatedTypeDescriptorHeader)

			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read swift.AssociatedTypeDescriptorHeader: %v", err)
			}

			aType.AssociatedTypeRecords = make([]swift.AssociatedTypeRecord, aType.AssociatedTypeDescriptorHeader.NumAssociatedTypes)
			if err := binary.Read(r, f.ByteOrder, &aType.AssociatedTypeRecords); err != nil {
				return nil, fmt.Errorf("failed to read []swift.AssociatedTypeRecord: %v", err)
			}

			currOffset += int64(binary.Size(swift.AssociatedTypeDescriptorHeader{}))

			accocTypes = append(accocTypes, aType)
		}

		return &accocTypes, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_assocty section")
}

// GetSwiftBuiltinTypes parses all the built-in types in the __TEXT.__swift5_builtin section
func (f *File) GetSwiftBuiltinTypes() (*[]swift.BuiltinType, error) {
	var builtins []swift.BuiltinType

	if sec := f.Section("__TEXT", "__swift5_builtin"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_builtin: %v", err)
		}

		builtInTypes := make([]swift.BuiltinTypeDescriptor, int(sec.Size)/binary.Size(swift.BuiltinTypeDescriptor{}))

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &builtInTypes); err != nil {
			return nil, fmt.Errorf("failed to read []swift.BuiltinTypeDescriptor: %v", err)
		}

		for idx, bType := range builtInTypes {
			currOffset := int64(sec.Offset) + int64(idx*binary.Size(swift.BuiltinTypeDescriptor{}))
			name, _, err := f.GetMangledTypeAtOffset(currOffset + int64(bType.TypeName))
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

		return &builtins, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_builtin section")
}

// GetSwiftClosures parses all the closure context objects in the __TEXT.__swift5_capture section
func (f *File) GetSwiftClosures() (*[]swift.CaptureDescriptor, error) {
	var closures []swift.CaptureDescriptor

	if sec := f.Section("__TEXT", "__swift5_capture"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_capture: %v", err)
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
				return nil, fmt.Errorf("failed to read swift.CaptureDescriptorHeader: %v", err)
			}

			currOffset += int64(binary.Size(capture.CaptureDescriptorHeader))

			if capture.CaptureDescriptorHeader.NumCaptureTypes > 0 {
				capture.CaptureTypeRecords = make([]swift.CaptureTypeRecord, capture.CaptureDescriptorHeader.NumCaptureTypes)
				if err := binary.Read(r, f.ByteOrder, &capture.CaptureTypeRecords); err != nil {
					return nil, fmt.Errorf("failed to read []swift.BuiltinTypeDescriptor: %v", err)
				}
				// for idx, capRecord := range capture.CaptureTypeRecords {
				// 	currOffset += int64(idx * binary.Size(swift.CaptureTypeRecord{}))
				// 	name, _, err := f.GetMangledTypeAtOffset(currOffset + int64(capRecord.MangledTypeName))
				// 	if err != nil {
				// 		return nil, fmt.Errorf("failed to read swift.CaptureTypeRecord.MangledTypeName; %v", err)
				// 	}
				// 	fmt.Println(name)
				// }
			}

			closures = append(closures, capture)
		}

		return &closures, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_capture section")
}

// GetMangledTypeAtOffset reads a mangled type at a given offset in the MachO
func (f *File) GetMangledTypeAtOffset(offset int64) (string, *stypes.TypeDescriptor, error) {

	if _, err := f.sr.Seek(offset, io.SeekStart); err != nil {
		return "", nil, fmt.Errorf("failed to Seek: %v", err)
	}

	var refType byte
	if err := binary.Read(f.sr, f.ByteOrder, &refType); err != nil {
		return "", nil, fmt.Errorf("failed to read possible symbolic reference type at offset %#x, %v", offset, err)
	}

	if refType >= byte(0x01) && refType <= byte(0x17) {

		var t32 int32
		if err := binary.Read(f.sr, f.ByteOrder, &t32); err != nil {
			return "", nil, fmt.Errorf("failed to read 32bit symbolic ref: %v", err)
		}

		switch refType {
		case 1:
			typeDescOffset := offset + int64(t32) + 1
			f.sr.Seek(typeDescOffset, io.SeekStart)
			var tDesc stypes.TypeDescriptor
			if err := binary.Read(f.sr, f.ByteOrder, &tDesc); err != nil {
				return "", nil, fmt.Errorf("failed to read stypes.TypeDescriptor: %v", err)
			}
			parentDescOffset := typeDescOffset + sizeOfInt32 + int64(tDesc.Parent)
			f.sr.Seek(parentDescOffset, io.SeekStart)
			var parentDesc stypes.TypeDescriptor
			if err := binary.Read(f.sr, f.ByteOrder, &parentDesc); err != nil {
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
			f.sr.Seek(offset+int64(t32)+1, io.SeekStart)
			var context uint64
			if err := binary.Read(f.sr, f.ByteOrder, &context); err != nil {
				return "", nil, fmt.Errorf("failed to read 32bit symbolic ref: %v", err)
			}
			// Check if context pointer is a dyld chain fixup REBASE
			if fixupchains.DcpArm64eIsRebase(context) {
				off, err := f.GetOffset(f.vma.Convert(context))
				if err != nil {
					return "", nil, fmt.Errorf("failed to GetOffset: %v", err)
				}
				f.sr.Seek(int64(off), io.SeekStart)

				var tDesc stypes.TypeDescriptor
				if err := binary.Read(f.sr, f.ByteOrder, &tDesc); err != nil {
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
		if _, err := f.sr.Read(int64Bytes); err != nil {
			return "", nil, fmt.Errorf("unsupported symbolic REF: %X, %#x", refType, offset+int64(binary.LittleEndian.Uint64(int64Bytes)))
		}
	} else { // regular string mangled type
		// revert the peek byte read
		if _, err := f.sr.Seek(-1, io.SeekCurrent); err != nil {
			return "", nil, fmt.Errorf("failed to Seek: %v", err)
		}
		s, err := bufio.NewReader(f.sr).ReadString('\x00')
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
