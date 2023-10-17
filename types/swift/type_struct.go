package swift

import (
	"encoding/binary"
	"io"
)

type TargetStructDescriptor struct {
	TargetTypeContextDescriptor
	NumFields               uint32
	FieldOffsetVectorOffset uint32
}

func (s TargetStructDescriptor) Size() int64 {
	return int64(
		int(s.TargetTypeContextDescriptor.Size()) +
			binary.Size(s.NumFields) +
			binary.Size(s.FieldOffsetVectorOffset))
}

func (s *TargetStructDescriptor) Read(r io.Reader, addr uint64) error {
	if err := s.TargetTypeContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &s.NumFields); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &s.FieldOffsetVectorOffset); err != nil {
		return err
	}
	return nil
}
