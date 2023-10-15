package swift

import (
	"encoding/binary"
	"io"
)

type RelativeDirectPointer struct {
	Address uint64
	RelOff  int32
}

func (r RelativeDirectPointer) GetAddress() uint64 {
	return uint64(int64(r.Address) + int64(r.RelOff))
}
func (r RelativeDirectPointer) IsSet() bool {
	return r.RelOff != 0
}

type TargetRelativeDirectPointer struct {
	Address uint64
	RelOff  int32
}

func (tr TargetRelativeDirectPointer) IsSet() bool {
	return tr.RelOff != 0
}
func (tr TargetRelativeDirectPointer) GetRelPtrAddress() uint64 {
	return uint64(int64(tr.Address) + int64(tr.RelOff))
}
func (tr TargetRelativeDirectPointer) GetAddress(r io.Reader) (uint64, error) {
	var pointerRelOff int32
	if err := binary.Read(r, binary.LittleEndian, &pointerRelOff); err != nil {
		return 0, err
	}
	return uint64(int64(tr.Address) + int64(tr.RelOff) + int64(pointerRelOff)), nil
}
