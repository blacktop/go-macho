// Code generated by "stringer -type=FieldDescriptorKind -linecomment -output field_string.go"; DO NOT EDIT.

package swift

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[FDKindStruct-0]
	_ = x[FDKindClass-1]
	_ = x[FDKindEnum-2]
	_ = x[FDKindMultiPayloadEnum-3]
	_ = x[FDKindProtocol-4]
	_ = x[FDKindClassProtocol-5]
	_ = x[FDKindObjCProtocol-6]
	_ = x[FDKindObjCClass-7]
}

const _FieldDescriptorKind_name = "structclassenummulti-payload enumprotocolclass protocolobjc protocolobjc class"

var _FieldDescriptorKind_index = [...]uint8{0, 6, 11, 15, 33, 41, 55, 68, 78}

func (i FieldDescriptorKind) String() string {
	if i >= FieldDescriptorKind(len(_FieldDescriptorKind_index)-1) {
		return "FieldDescriptorKind(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _FieldDescriptorKind_name[_FieldDescriptorKind_index[i]:_FieldDescriptorKind_index[i+1]]
}
