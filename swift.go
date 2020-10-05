package macho

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types/swift"
	fieldmd "github.com/blacktop/go-macho/types/swift/fields"
	"github.com/blacktop/go-macho/types/swift/protocols"
	stypes "github.com/blacktop/go-macho/types/swift/types"
)

const sizeOfInt32 = 4

// GetSwiftProtocols parses all the fields in the __TEXT.__swift5_fieldmd section
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
			kind := pcd.ConformanceFlags.GetTypeReferenceKind()
			fmt.Printf("%#v\n", kind)
			protoConfDescs = append(protoConfDescs, pcd)
		}

		return &protoConfDescs, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_protos section")
}

func (f *File) GetSwiftTypes() (*[]stypes.TypeDescriptor, error) {
	var classes []stypes.TypeDescriptor

	if sec := f.Section("__TEXT", "__swift5_types"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_types: %v", err)
		}

		r := bytes.NewReader(dat)

		relOffsets := make([]int32, len(dat)/sizeOfInt32)

		if err := binary.Read(r, f.ByteOrder, &relOffsets); err != nil {
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
			parent, err := f.GetCStringAtOffset(offset + 4 + int64(tDesc.Parent))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}
			fmt.Printf("parent: %s %v\n", parent, []byte(parent))

			name, err := f.GetCStringAtOffset(offset + 8 + int64(tDesc.Name))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}
			fmt.Println(name)

			f.sr.Seek(offset+16+int64(tDesc.FieldDescriptor), io.SeekStart)

			var fDesc fieldmd.Header
			if err := binary.Read(f.sr, f.ByteOrder, &fDesc); err != nil {
				return nil, fmt.Errorf("failed to read swift.Header: %v", err)
			}
			fmt.Println(fDesc)

			name, err = f.GetCStringAtOffset(offset + 16 + int64(tDesc.FieldDescriptor) + int64(fDesc.MangledTypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring: %v", err)
			}
			fmt.Println(name)

			classes = append(classes, tDesc)
		}

		return &classes, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_types section")
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
			var err error
			var superClass string

			peek := make([]byte, 60)
			currOffset, _ := r.Seek(0, io.SeekCurrent)
			currOffset += int64(sec.Offset)

			var fDesc fieldmd.FieldDescriptor
			err = binary.Read(r, f.ByteOrder, &fDesc.Header)

			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read swift.Header: %v", err)
			}

			typeName, _, err := f.GetMangledTypeAtOffset(currOffset + int64(fDesc.Header.MangledTypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read MangledTypeName: %v", err)
			}

			if fDesc.Header.Superclass == 0 {
				superClass = "<ROOT>"
			} else {
				superClass, err = f.GetCStringAtOffset(currOffset + sizeOfInt32 + int64(fDesc.Header.Superclass))
				if err != nil {
					return nil, fmt.Errorf("failed to read cstring: %v", err)
				}
				fmt.Printf("superClass: %s %v\n", superClass, []byte(superClass))
			}

			fDesc.FieldRecords = make([]fieldmd.RecordT, fDesc.Header.NumFields)
			if err := binary.Read(r, f.ByteOrder, &fDesc.FieldRecords); err != nil {
				return nil, fmt.Errorf("failed to read []fieldmd.RecordT: %v", err)
			}

			currOffset += int64(binary.Size(fieldmd.Header{}))

			var records []fieldmd.Record
			for idx, record := range fDesc.FieldRecords {
				var name string

				currOffset += int64(idx * int(fDesc.FieldRecordSize))

				if record.MangledTypeName != 0 {
					typeName, _, err = f.GetMangledTypeAtOffset(currOffset + 4 + int64(record.MangledTypeName))
					if err != nil {
						return nil, fmt.Errorf("failed to read record.MangledTypeName; %v", err)
					}

					typeName = "$s" + typeName
					fmt.Printf("type: %s %v\n", typeName, []byte(typeName))

					f.sr.ReadAt(peek, currOffset+4+int64(record.MangledTypeName)-16)
					fmt.Printf("%s\n", hex.Dump(peek))
				}

				name, err = f.GetCStringAtOffset(currOffset + 8 + int64(record.FieldName))
				if err != nil {
					return nil, fmt.Errorf("failed to read cstring: %v", err)
				}

				fmt.Println("name:", name)
				f.sr.ReadAt(peek, currOffset+8+int64(record.FieldName)-16)
				fmt.Printf("%s\n", hex.Dump(peek))

				records = append(records, fieldmd.Record{
					Name: name,
					// Type:            typeBytes,
					MangledTypeName: typeName,
					Flags:           record.Flags.String(),
				})
			}

			fields = append(fields, fieldmd.Field{
				// Type:            typeBytes,
				MangledTypeName: typeName,
				SuperClass:      superClass,
				Kind:            fDesc.Kind.String(),
				Records:         records,
				Descriptor:      fDesc,
			})
		}

		return &fields, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_fieldmd section")
}

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
func (f *File) GetSwiftBuiltinTypes() (*[]swift.BuiltinTypeDescriptor, error) {
	var builtInTypes []swift.BuiltinTypeDescriptor

	if sec := f.Section("__TEXT", "__swift5_builtin"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_builtin: %v", err)
		}

		builtInTypes = make([]swift.BuiltinTypeDescriptor, int(sec.Size)/binary.Size(swift.BuiltinTypeDescriptor{}))

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &builtInTypes); err != nil {
			return nil, fmt.Errorf("failed to read []swift.BuiltinTypeDescriptor: %v", err)
		}

		for idx, bType := range builtInTypes {
			currOffset := int64(sec.Offset) + int64(idx*binary.Size(swift.BuiltinTypeDescriptor{}))
			name, _, err := f.GetMangledTypeAtOffset(currOffset + int64(bType.TypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring at 0x%x; %v", currOffset+int64(bType.TypeName), err)
			}
			fmt.Println("name:", name)
		}

		return &builtInTypes, nil
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

			if capture.CaptureDescriptorHeader.NumCaptureTypes > 0 {
				capture.CaptureTypeRecords = make([]swift.CaptureTypeRecord, capture.CaptureDescriptorHeader.NumCaptureTypes)
				if err := binary.Read(r, f.ByteOrder, &capture.CaptureTypeRecords); err != nil {
					return nil, fmt.Errorf("failed to read []swift.BuiltinTypeDescriptor: %v", err)
				}
			}

			// currOffset += int64(binary.Size(capture))

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

	r := bufio.NewReader(f.sr)

	peekByte, err := r.Peek(1)
	if err != nil {
		return "", nil, fmt.Errorf("failed to Peek at offset 0x%x, %v", offset, err)
	}

	if peekByte[0] >= byte(0x01) && peekByte[0] <= byte(0x17) {
		refType, err := r.ReadByte()
		if err != nil {
			return "", nil, fmt.Errorf("failed to ReadByte at offset 0x%x, %v", offset, err)
		}

		var t32 int32
		if err := binary.Read(r, f.ByteOrder, &t32); err != nil {
			return "", nil, fmt.Errorf("failed to read 32bit symbolic ref: %v", err)
		}
		fmt.Printf("REF: %X, 0x%x\n", refType, offset+int64(t32))

		switch refType {
		case 1:
			f.sr.Seek(offset+int64(t32)+1, io.SeekStart)
			var tDesc stypes.TypeDescriptor
			if err := binary.Read(f.sr, f.ByteOrder, &tDesc); err != nil {
				return "", nil, fmt.Errorf("failed to read stypes.TypeDescriptor: %v", err)
			}

			name, err := f.GetCStringAtOffset(offset + int64(t32) + 1 + 8 + int64(tDesc.Name))
			if err != nil {
				return "", nil, fmt.Errorf("failed to read cstring: %v", err)
			}
			fmt.Println("name:", name, tDesc.Flags)
			return name, &tDesc, nil
		case 2:
			f.sr.Seek(offset+int64(t32)+1, io.SeekStart)
			var context uint64
			if err := binary.Read(f.sr, f.ByteOrder, &context); err != nil {
				return "", nil, fmt.Errorf("failed to read 32bit symbolic ref: %v", err)
			}
			off, err := f.GetOffset(f.convertToVMAddr(context))
			if err != nil {
				// return "", nil, fmt.Errorf("failed to GetOffset: %v", err)
				fmt.Printf("failed to GetOffset: %v\n", err)
				return "import", nil, nil
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

	} else if peekByte[0] >= byte(0x18) && peekByte[0] <= byte(0x1F) {
		refType, err := r.ReadByte()
		if err != nil {
			return "", nil, fmt.Errorf("failed to ReadByte at offset 0x%x, %v", offset, err)
		}
		int64Bytes := make([]byte, 8)
		if _, err := r.Read(int64Bytes); err != nil {
			fmt.Printf("REF: %X, 0x%x\n", refType, offset+int64(binary.LittleEndian.Uint64(int64Bytes)))
		}
	} else {
		s, err := bufio.NewReader(f.sr).ReadString('\x00')
		if err != nil {
			return "", nil, fmt.Errorf("failed to ReadBytes at offset 0x%x, %v", offset, err)
		}
		return strings.Trim(s, "\x00"), nil, nil
	}

	return "", nil, fmt.Errorf("type data not found")
}
