package types

import (
	"fmt"

	"github.com/blacktop/go-macho/types/swift/fields"
)

//go:generate stringer -type=ContextDescriptorKind -output types_string.go

// __TEXT.__swift5_types
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a nominal type descriptor in the __TEXT.__const section.

type ContextDescriptorKind uint8

const (
	// This context descriptor represents a module.
	Module ContextDescriptorKind = 0

	/// This context descriptor represents an extension.
	Extension ContextDescriptorKind = 1

	/// This context descriptor represents an anonymous possibly-generic context
	/// such as a function body.
	Anonymous ContextDescriptorKind = 2

	/// This context descriptor represents a protocol context.
	Protocol ContextDescriptorKind = 3

	/// This context descriptor represents an opaque type alias.
	OpaqueType ContextDescriptorKind = 4

	/// First kind that represents a type of any sort.
	TypeFirst = 16

	/// This context descriptor represents a class.
	Class ContextDescriptorKind = TypeFirst

	/// This context descriptor represents a struct.
	Struct ContextDescriptorKind = TypeFirst + 1

	/// This context descriptor represents an enum.
	Enum ContextDescriptorKind = TypeFirst + 2

	/// Last kind that represents a type of any sort.
	TypeLast = 31
)

type TypeContextDescriptorFlags uint16

const (
	// All of these values are bit offsets or widths.
	// Generic flags build upwards from 0.
	// Type-specific flags build downwards from 15.

	/// Whether there's something unusual about how the metadata is
	/// initialized.
	///
	/// Meaningful for all type-descriptor kinds.
	MetadataInitialization       TypeContextDescriptorFlags = 0
	MetadataInitialization_width TypeContextDescriptorFlags = 2

	/// Set if the type has extended import information.
	///
	/// If true, a sequence of strings follow the null terminator in the
	/// descriptor, terminated by an empty string (i.e. by two null
	/// terminators in a row).  See TypeImportInfo for the details of
	/// these strings and the order in which they appear.
	///
	/// Meaningful for all type-descriptor kinds.
	HasImportInfo TypeContextDescriptorFlags = 2

	/// Set if the type descriptor has a pointer to a list of canonical
	/// prespecializations.
	HasCanonicalMetadataPrespecializations TypeContextDescriptorFlags = 3

	// Type-specific flags:

	/// Set if the class is an actor.
	///
	/// Only meaningful for class descriptors.
	Class_IsActor TypeContextDescriptorFlags = 7

	/// Set if the class is a default actor class.  Note that this is
	/// based on the best knowledge available to the class; actor
	/// classes with resilient superclassess might be default actors
	/// without knowing it.
	///
	/// Only meaningful for class descriptors.
	Class_IsDefaultActor TypeContextDescriptorFlags = 8

	/// The kind of reference that this class makes to its resilient superclass
	/// descriptor.  A TypeReferenceKind.
	///
	/// Only meaningful for class descriptors.
	Class_ResilientSuperclassReferenceKind       TypeContextDescriptorFlags = 9
	Class_ResilientSuperclassReferenceKind_width TypeContextDescriptorFlags = 3

	/// Whether the immediate class members in this metadata are allocated
	/// at negative offsets.  For now, we don't use this.
	Class_AreImmediateMembersNegative TypeContextDescriptorFlags = 12

	/// Set if the context descriptor is for a class with resilient ancestry.
	///
	/// Only meaningful for class descriptors.
	Class_HasResilientSuperclass TypeContextDescriptorFlags = 13

	/// Set if the context descriptor includes metadata for dynamically
	/// installing method overrides at metadata instantiation time.
	Class_HasOverrideTable TypeContextDescriptorFlags = 14

	/// Set if the context descriptor includes metadata for dynamically
	/// constructing a class's vtables at metadata instantiation time.
	///
	/// Only meaningful for class descriptors.
	Class_HasVTable TypeContextDescriptorFlags = 15
)

// TODO: should I also add `MetadataInitializationKind`flag bit values?

type ContextDescriptorFlags uint32

func (f ContextDescriptorFlags) Kind() ContextDescriptorKind {
	return ContextDescriptorKind(f & 0x1F)
}
func (f ContextDescriptorFlags) IsGeneric() bool {
	return (f & 0x80) != 0
}
func (f ContextDescriptorFlags) IsUnique() bool {
	return (f & 0x40) != 0
}
func (f ContextDescriptorFlags) Version() uint8 {
	return uint8(f >> 8 & 0xFF)
}
func (f ContextDescriptorFlags) KindSpecificFlags() TypeContextDescriptorFlags {
	return TypeContextDescriptorFlags(f >> 16 & 0xFFFF)
}
func (f ContextDescriptorFlags) String() string {
	return fmt.Sprintf("kind: %s, generic: %t, unique: %t, version: %d, kind_flags: %#x",
		f.Kind(),
		f.IsGeneric(),
		f.IsUnique(),
		f.Version(),
		f.KindSpecificFlags())
}

type Type struct {
	Address uint64
	Name    string
}

type TypeDescriptor struct {
	Address           uint64
	Parent            Type
	Name              string
	AccessFunction    uint64
	FieldOffsetVector []uint32
	Fields            []*fields.Field
	Type              any
}

type TargetContextDescriptor struct {
	Flags                 ContextDescriptorFlags
	ParentOffset          int32
	NameOffset            int32
	AccessFunctionOffset  int32
	FieldDescriptorOffset int32
}

type EnumDescriptor struct {
	TargetContextDescriptor
	NumPayloadCasesAndPayloadSizeOffset uint32
	NumEmptyCases                       uint32
}

type TargetStructDescriptor struct {
	TargetContextDescriptor
	NumFields               uint32
	FieldOffsetVectorOffset uint32
}

type TargetClassDescriptor struct {
	TargetContextDescriptor
	SuperclassType              int32
	MetadataNegativeSizeInWords uint32
	MetadataPositiveSizeInWords uint32
	NumImmediateMembers         uint32
	NumFields                   uint32
	FieldOffsetVectorOffset     uint32 // ??
}

type mdFlags uint32

const (
	Method = iota
	Init
	Getter
	Setter
	ModifyCoroutine
	ReadCoroutine
)

func (f mdFlags) Kind() string {
	switch f & 0x0F {
	case Method:
		return "method"
	case Init:
		return "init"
	case Getter:
		return "getter"
	case Setter:
		return "setter"
	case ModifyCoroutine:
		return "modify coroutine"
	case ReadCoroutine:
		return "read coroutine"
	default:
		return "unknown"
	}
}
func (f mdFlags) IsInstance() bool {
	return (f & 0x10) != 0
}
func (f mdFlags) IsDynamic() bool {
	return (f & 0x20) != 0
}

type MethodDescriptor struct {
	Flags mdFlags
	Impl  int32
}
