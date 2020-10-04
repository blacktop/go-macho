package types

import "fmt"

//go:generate stringer -type=CDKind -output types_string.go

// __TEXT.__swift5_types
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a nominal type descriptor in the __TEXT.__const section.

type CDKind uint8

const (
	// This context descriptor represents a module.
	Module CDKind = 0

	/// This context descriptor represents an extension.
	Extension CDKind = 1

	/// This context descriptor represents an anonymous possibly-generic context
	/// such as a function body.
	Anonymous CDKind = 2

	/// This context descriptor represents a protocol context.
	Protocol CDKind = 3

	/// This context descriptor represents an opaque type alias.
	OpaqueType CDKind = 4

	/// First kind that represents a type of any sort.
	TypeFirst = 16

	/// This context descriptor represents a class.
	Class CDKind = TypeFirst

	/// This context descriptor represents a struct.
	Struct CDKind = TypeFirst + 1

	/// This context descriptor represents an enum.
	Enum CDKind = TypeFirst + 2

	/// Last kind that represents a type of any sort.
	TypeLast = 31
)

type TypeDescFlag uint32

func (f TypeDescFlag) Kind() CDKind {
	return CDKind(f & 0x1F)
}
func (f TypeDescFlag) IsGeneric() bool {
	return f&0x80 != 0
}
func (f TypeDescFlag) IsUnique() bool {
	return f&0x40 != 0
}
func (f TypeDescFlag) Version() uint8 {
	return uint8(f >> 8 & 0xFF)
}
func (f TypeDescFlag) KindSpecificFlags() uint16 {
	return uint16(f >> 16 & 0xFFFF)
}
func (f TypeDescFlag) String() string {
	return fmt.Sprintf("kind: %s, generic: %t, unique: %t, version: %d, kind_flags: 0x%x",
		f.Kind(),
		f.IsGeneric(),
		f.IsUnique(),
		f.Version(),
		f.KindSpecificFlags())
}

type TypeDescriptor struct {
	Flags           TypeDescFlag
	Parent          int32
	Name            int32
	AccessFunction  int32
	FieldDescriptor int32
}

type EnumDescriptor struct {
	TypeDescriptor
	NumPayloadCasesAndPayloadSizeOffset uint32
	NumEmptyCases                       uint32
}

type StructDescriptor struct {
	TypeDescriptor
	NumFields               uint32
	FieldOffsetVectorOffset uint32
}

type ClassDescriptor struct {
	TypeDescriptor
	SuperclassType              int32
	MetadataNegativeSizeInWords uint32
	MetadataPositiveSizeInWords uint32
	NumImmediateMembers         uint32
	NumFields                   uint32
	FieldOffsetVectorOffset     uint32 // ??
}
