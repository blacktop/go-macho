package fields

//go:generate stringer -type=FieldDescriptorKind,RecordFlags -output fields_string.go

// __TEXT.__swift5_fieldmd
// This section contains an array of field descriptors.
// A field descriptor contains a collection of field records for a single class,
// struct or enum declaration. Each field descriptor can be a different length depending on how many field records the type contains.

type FieldDescriptorKind uint16

const (
	// Swift nominal types.
	Struct FieldDescriptorKind = iota
	Class
	Enum

	// Fixed-size multi-payload enums have a special descriptor format that
	// encodes spare bits.
	//
	// FIXME: Actually implement this. For now, a descriptor with this kind
	// just means we also have a builtin descriptor from which we get the
	// size and alignment.
	MultiPayloadEnum

	// A Swift opaque protocol. There are no fields, just a record for the
	// type itself.
	Protocol

	// A Swift class-bound protocol.
	ClassProtocol

	// An Objective-C protocol, which may be imported or defined in Swift.
	ObjCProtocol

	// An Objective-C class, which may be imported or defined in Swift.
	// In the former case, field type metadata is not emitted, and
	// must be obtained from the Objective-C runtime.
	ObjCClass
)

type Field struct {
	TypeName    string
	MangledName string
	SuperClass  string
	Kind        string
	Records     []FieldRecord
	Offset      int64
	Descriptor  FieldDescriptor
}

func (f Field) IsEnum() bool {
	return f.Descriptor.Kind == Enum || f.Descriptor.Kind == MultiPayloadEnum
}
func (f Field) IsClass() bool {
	return f.Descriptor.Kind == Class || f.Descriptor.Kind == ObjCClass
}
func (f Field) IsProtocol() bool {
	return f.Descriptor.Kind == Protocol || f.Descriptor.Kind == ClassProtocol || f.Descriptor.Kind == ObjCProtocol
}

type Header struct {
	MangledTypeName int32
	Superclass      int32
	Kind            FieldDescriptorKind
	FieldRecordSize uint16
	NumFields       uint32
}

type FieldDescriptor struct {
	Header
	FieldRecords []FieldRecordType
}

type FieldRecord struct {
	Name            string
	MangledTypeName string
	Flags           string
}

type RecordFlags uint32

const (
	// IsIndirectCase is this an indirect enum case?
	IsIndirectCase RecordFlags = 0x1
	// IsVar is this a mutable `var` property?
	IsVar RecordFlags = 0x2
	// IsArtificial is this an artificial field?
	IsArtificial RecordFlags = 0x4
)

type FieldRecordType struct {
	Flags           RecordFlags
	MangledTypeName int32
	FieldName       int32
}
