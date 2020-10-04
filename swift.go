package macho

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/blacktop/go-macho/types/swift"
	fieldmd "github.com/blacktop/go-macho/types/swift/fields"
	stypes "github.com/blacktop/go-macho/types/swift/types"
)

const sizeOfInt32 = 4

func (f *File) GetSwiftProtocols() (*[]swift.ProtocolDescriptor, error) {
	var protoDescs []swift.ProtocolDescriptor

	if sec := f.Section("__TEXT", "__swift5_protos"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_protos: %v", err)
		}

		r := bytes.NewReader(dat)

		relOffsets := make([]int32, len(dat)/sizeOfInt32)

		if err := binary.Read(r, f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			offset := int64(sec.Offset+uint32(idx*sizeOfInt32)) + int64(relOff)

			f.sr.Seek(offset, io.SeekStart)

			var proto swift.ProtocolDescriptor
			if err := binary.Read(f.sr, f.ByteOrder, &proto); err != nil {
				return nil, fmt.Errorf("failed to read swift.ProtocolDescriptor: %v", err)
			}

			name, err := f.GetCStringAtOffset(offset + 8 + int64(proto.Name))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring:%v", err)
			}
			fmt.Println(name)

			protoDescs = append(protoDescs, proto)
		}

		return &protoDescs, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_protos section")
}

func (f *File) GetSwiftProtocolConformances() (*[]swift.ProtocolConformanceDescriptor, error) {
	var protoConfDescs []swift.ProtocolConformanceDescriptor

	if sec := f.Section("__TEXT", "__swift5_proto"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __swift5_protos: %v", err)
		}

		r := bytes.NewReader(dat)

		relOffsets := make([]int32, len(dat)/sizeOfInt32)

		if err := binary.Read(r, f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			offset := int64(sec.Offset+uint32(idx*sizeOfInt32)) + int64(relOff)

			f.sr.Seek(offset, io.SeekStart)

			var pcd swift.ProtocolConformanceDescriptor
			if err := binary.Read(f.sr, f.ByteOrder, &pcd); err != nil {
				return nil, fmt.Errorf("failed to read swift.ProtocolDescriptor: %v", err)
			}

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
			var typeName string
			var typeBytes []byte
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

			typeBytes, err = f.GetMangledTypeAtOffset(currOffset + int64(fDesc.Header.MangledTypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read MangledTypeName: %v", err)
			}
			fmt.Printf("field type: %s %v\n", string(typeName), typeBytes)

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
				var typeBytes []byte
				var typeName string

				currOffset += int64(idx * int(fDesc.FieldRecordSize))

				if record.MangledTypeName != 0 {
					typeBytes, err = f.GetMangledTypeAtOffset(currOffset + 4 + int64(record.MangledTypeName))
					if err != nil {
						return nil, fmt.Errorf("failed to read record.MangledTypeName; %v", err)
					}
					if typeBytes[0] > 0x1F {
						typeName = "$s" + string(typeBytes)
						fmt.Printf("type: %s %v\n", typeName, []byte(typeName))
					}
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
					Name:            name,
					Type:            typeBytes,
					MangledTypeName: typeName,
					Flags:           record.Flags.String(),
				})
			}

			fields = append(fields, fieldmd.Field{
				Type:            typeBytes,
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
			name, err := f.GetCStringAtOffset(currOffset + int64(bType.TypeName))
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring at 0x%x; %v", currOffset+int64(bType.TypeName), err)
			}
			fmt.Println("name:", name)
		}

		return &builtInTypes, nil
	}
	return nil, fmt.Errorf("file does not contain a __swift5_builtin section")
}

// GetMangledTypeAtOffset reads a mangled type at a given offset in the MachO
func (f *File) GetMangledTypeAtOffset(offset int64) ([]byte, error) {
	if _, err := f.sr.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to Seek: %v", err)
	}

	s, err := bufio.NewReader(f.sr).ReadBytes('\x00')
	if err != nil {
		return nil, fmt.Errorf("failed to ReadBytes as offset 0x%x, %v", offset, err)
	}

	if len(s) > 0 {
		ss := bytes.TrimRight(s, "\x00")
		if bytes.IndexByte(ss, byte(0xFF)) > 0 {
			ss = ss[:bytes.IndexByte(s, byte(0xFF))]
		}
		if len(ss) > 0 {
			return ss, nil
		}
		return s, nil
	}

	return nil, fmt.Errorf("type data not found")
}
