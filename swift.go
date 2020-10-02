package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/pkg/swift"
)

const sizeOfInt32 = 4

func (f *File) GetSwiftProtocols() (*[]swift.ProtocolDescriptor, error) {
	var protoDescs []swift.ProtocolDescriptor
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__TEXT") {
			if sec := f.Section(s.Name, "__swift5_protos"); sec != nil {
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
						return nil, fmt.Errorf("failed to read cstring at 0x%x; %v", offset+8+int64(proto.Name), err)
					}
					fmt.Println(name)

					protoDescs = append(protoDescs, proto)
				}

				return &protoDescs, nil
			}
		}
	}
	return nil, fmt.Errorf("file does not contain a __swift5_protos section")
}
func (f *File) GetSwiftTypes() (*[]swift.ClassDescriptor, error) {
	var classes []swift.ClassDescriptor
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__TEXT") {
			if sec := f.Section(s.Name, "__swift5_types"); sec != nil {
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

					var proto swift.ClassDescriptor
					if err := binary.Read(f.sr, f.ByteOrder, &proto); err != nil {
						return nil, fmt.Errorf("failed to read swift.ClassDescriptor: %v", err)
					}

					name, err := f.GetCStringAtOffset(offset + 8 + int64(proto.Name))
					if err != nil {
						return nil, fmt.Errorf("failed to read cstring at 0x%x; %v", offset+8+int64(proto.Name), err)
					}
					fmt.Println(name)

					classes = append(classes, proto)
				}

				return &classes, nil
			}
		}
	}
	return nil, fmt.Errorf("file does not contain a __swift5_types section")
}
