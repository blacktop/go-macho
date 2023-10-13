package swift

type TargetEnumDescriptor struct {
	TargetTypeContextDescriptor
	NumPayloadCasesAndPayloadSizeOffset uint32
	NumEmptyCases                       uint32
}

func (e TargetEnumDescriptor) GetNumPayloadCases() uint32 {
	return e.NumPayloadCasesAndPayloadSizeOffset & 0x00FFFFFF
}
func (e TargetEnumDescriptor) GetNumCases() uint32 {
	return e.GetNumPayloadCases() + e.NumEmptyCases
}
func (e TargetEnumDescriptor) GetPayloadSizeOffset() uint32 {
	return (e.NumPayloadCasesAndPayloadSizeOffset & 0xFF000000) >> 24
}
