package swift

// credit: https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html

// ProtocolDescriptor in __TEXT.__swift5_protos
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol descriptor in the __TEXT.__const section.
type ProtocolDescriptor struct {
	Flags                      uint32
	Parent                     int32
	Name                       int32
	NumRequirementsInSignature uint32
	NumRequirements            uint32
	AssociatedTypeNames        int32
}

// ProtocolConformanceDescriptor in __TEXT.__swift5_proto
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol conformance descriptor in the __TEXT.__const section.
type ProtocolConformanceDescriptor struct {
	ProtocolDescriptor    int32
	NominalTypeDescriptor int32
	ProtocolWitnessTable  int32
	ConformanceFlags      uint32
}

// __TEXT.__swift5_types
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a nominal type descriptor in the __TEXT.__const section.

type EnumDescriptor struct {
	Flags                               uint32
	Parent                              int32
	Name                                int32
	AccessFunction                      int32
	FieldDescriptor                     int32
	NumPayloadCasesAndPayloadSizeOffset uint32
	NumEmptyCases                       uint32
}

type StructDescriptor struct {
	Flags                   uint32
	Parent                  int32
	Name                    int32
	AccessFunction          int32
	FieldDescriptor         int32
	NumFields               uint32
	FieldOffsetVectorOffset uint32
}

type ClassDescriptor struct {
	Flags                       uint32
	Parent                      int32
	Name                        int32
	AccessFunction              int32
	FieldDescriptor             int32
	SuperclassType              int32
	MetadataNegativeSizeInWords uint32
	MetadataPositiveSizeInWords uint32
	NumImmediateMembers         uint32
	NumFields                   uint32
	FieldOffsetVectorOffset     uint32 // ??
}

// __TEXT.__swift5_fieldmd
// This section contains an array of field descriptors.
// A field descriptor contains a collection of field records for a single class,
// struct or enum declaration. Each field descriptor can be a different length depending on how many field records the type contains.

type FieldRecord struct {
	Flags           uint32
	MangledTypeName int32
	FieldName       int32
}

type FieldDescriptor struct {
	MangledTypeName int32
	Superclass      int32
	Kind            uint16
	FieldRecordSize uint16
	NumFields       uint32
	FieldRecords    []FieldRecord
}

// __TEXT.__swift5_assocty
// This section contains an array of associated type descriptors.
// An associated type descriptor contains a collection of associated type records for a conformance.
// An associated type records describe the mapping from an associated type to the type witness of a conformance.

type AssociatedTypeRecord struct {
	Name                int32
	SubstitutedTypeName int32
}

type AssociatedTypeDescriptor struct {
	ConformingTypeName       int32
	ProtocolTypeName         int32
	NumAssociatedTypes       uint32
	AssociatedTypeRecordSize uint32
	AssociatedTypeRecords    []AssociatedTypeRecord
}

// __TEXT.__swift5_builtin
// This section contains an array of builtin type descriptors.
// A builtin type descriptor describes the basic layout information about any builtin types referenced from other sections.

type BuiltinTypeDescriptor struct {
	TypeName            int32
	Size                uint32
	AlignmentAndFlags   uint32
	Stride              uint32
	NumExtraInhabitants uint32
}

// __TEXT.__swift5_capture
// Capture descriptors describe the layout of a closure context object.
// Unlike nominal types, the generic substitutions for a closure context come from the object, and not the metadata.

type CaptureTypeRecord struct {
	MangledTypeName int32
}

type MetadataSourceRecord struct {
	MangledTypeName       int32
	MangledMetadataSource int32
}

type CaptureDescriptor struct {
	NumCaptureTypes       uint32
	NumMetadataSources    uint32
	NumBindings           uint32
	CaptureTypeRecords    []CaptureTypeRecord
	MetadataSourceRecords []MetadataSourceRecord
}
