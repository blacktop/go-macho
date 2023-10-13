package swift

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
