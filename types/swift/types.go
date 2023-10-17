package swift

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/blacktop/go-macho/types"
)

//go:generate stringer -type ContextDescriptorKind,TypeReferenceKind,MetadataInitializationKind -linecomment -output types_string.go

// __TEXT.__swift5_types
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a nominal type descriptor in the __TEXT.__const section.

type Type struct {
	Address        uint64
	Parent         *TargetModuleContext
	Name           string
	SuperClass     string
	Kind           ContextDescriptorKind
	AccessFunction uint64
	FieldOffsets   []int32
	Generic        *TargetTypeGenericContextDescriptorHeader
	VTable         *VTable
	Fields         []Field
	Type           any
}

func (t Type) IsCImportedModuleName() bool {
	if t.Kind == CDKindModule {
		return t.Name == MANGLING_MODULE_OBJC
	}
	return false
}

func (t Type) String() string {
	return t.dump(false)
}
func (t Type) Verbose() string {
	return t.dump(true)
}
func (t Type) dump(verbose bool) string {
	var addr string
	switch t.Kind {
	case CDKindModule:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s", addr, t.Kind, t.Name)
	case CDKindExtension:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s.%s", addr, t.Kind, t.Parent.Name, t.Name)
	case CDKindAnonymous:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s", addr, t.Kind, t.Name)
	case CDKindProtocol:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s", addr, t.Kind, t.Name)
	case CDKindOpaqueType:
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s", addr, t.Kind, t.Name)
	case CDKindClass:
		var fields []string
		for _, f := range t.Fields {
			for _, r := range f.Records {
				var typ string
				if len(r.MangledType) > 0 {
					if strings.Contains(r.MangledType, "()") {
						typ = fmt.Sprintf(" = %s", r.MangledType)
					} else {
						typ = fmt.Sprintf(": %s", r.MangledType)
					}
				}
				if verbose {
					addr = fmt.Sprintf("/* %#x */ ", f.Address)
				}
				fields = append(fields, fmt.Sprintf("    %s%s %s%s", addr, r.Flags, strings.Replace(r.Name, "$__lazy_storage_$_", "lazy ", 1), typ))
			}
		}
		var meths []string
		if t.VTable != nil {
			for _, m := range t.VTable.Methods {
				var static string
				if !m.Flags.IsInstance() {
					static = "static "
				}
				sym := m.Symbol
				if m.Symbol == "" && m.Impl == 0 {
					sym = fmt.Sprintf("/* <stripped> %s */", m.Flags.String(""))
				} else if m.Symbol == "" && m.Impl != 0 {
					sym = fmt.Sprintf("%sfunc sub_%x // %s", static, m.Address, m.Flags.String(""))
				} else {
					sym = fmt.Sprintf("%sfunc %s // %s", static, sym, m.Flags.String(""))
				}
				if verbose {
					addr = fmt.Sprintf("/* %#x */ ", m.Address)
				}
				meths = append(meths, fmt.Sprintf("    %s%s", addr, sym))
			}
		}
		if len(fields) == 0 && len(meths) == 0 {
			if verbose {
				addr = fmt.Sprintf(" // %#x", t.Address)
			}
			return fmt.Sprintf("%s %s.%s {}%s\n", t.Kind, t.Parent.Name, t.Name, addr)
		}
		if len(fields) > 0 {
			fields = append([]string{"  /* fields */"}, fields...)
		}
		if len(meths) > 0 {
			if len(fields) > 0 {
				meths = append([]string{"\n  /* methods */"}, meths...)
			} else {
				meths = append([]string{"  /* methods */"}, meths...)
			}
		}
		var superClass string
		if t.SuperClass != "" {
			superClass = fmt.Sprintf(": %s", t.SuperClass)
		}
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		return fmt.Sprintf("%s%s %s.%s%s {\n%s%s\n}", addr, t.Kind, t.Parent.Name, t.Name, superClass, strings.Join(fields, "\n"), strings.Join(meths, "\n"))
	case CDKindStruct:
		var fields []string
		for _, f := range t.Fields {
			for _, r := range f.Records {
				if verbose {
					addr = fmt.Sprintf(" // %#x", t.Address)
				}
				var typ string
				if len(r.MangledType) > 0 {
					if strings.Contains(r.MangledType, "()") {
						typ = fmt.Sprintf(" = %s", r.MangledType)
					} else {
						typ = fmt.Sprintf(": %s", r.MangledType)
					}
				}
				fields = append(fields, fmt.Sprintf("    %s %s%s%s", r.Flags, r.Name, typ, addr))
			}
		}
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		if len(fields) == 0 {
			return fmt.Sprintf("%s%s %s.%s {}", addr, t.Kind, t.Parent.Name, t.Name)
		}
		return fmt.Sprintf("%s%s %s.%s {\n%s\n}", addr, t.Kind, t.Parent.Name, t.Name, strings.Join(fields, "\n"))
	case CDKindEnum:
		var fields []string
		for _, f := range t.Fields {
			for _, r := range f.Records {
				cs := "case"
				if r.Flags.String() == "indirect case" {
					cs = "indirect case"
				}
				var typ string
				if len(r.MangledType) > 0 {
					typ = fmt.Sprintf(": %s", r.MangledType)
				}
				if verbose {
					addr = fmt.Sprintf(" // %#x", f.Address)
				}
				fields = append(fields, fmt.Sprintf("    %s %s%s%s", cs, r.Name, typ, addr))
			}
		}
		if verbose {
			addr = fmt.Sprintf("// %#x\n", t.Address)
		}
		if len(fields) == 0 {
			return fmt.Sprintf("%s%s %s.%s {}", addr, t.Kind, t.Parent.Name, t.Name)
		}
		return fmt.Sprintf("%s%s %s.%s {\n%s\n}", addr, t.Kind, t.Parent.Name, t.Name, strings.Join(fields, "\n"))
	default:
		return fmt.Sprintf("unknown type %s", t.Name)
	}
}

type ContextDescriptorKind uint8

const (
	// This context descriptor represents a module.
	CDKindModule ContextDescriptorKind = 0 // module

	/// This context descriptor represents an extension.
	CDKindExtension ContextDescriptorKind = 1 // extension

	/// This context descriptor represents an anonymous possibly-generic context
	/// such as a function body.
	CDKindAnonymous ContextDescriptorKind = 2 // anonymous

	/// This context descriptor represents a protocol context.
	CDKindProtocol ContextDescriptorKind = 3 // protocol

	/// This context descriptor represents an opaque type alias.
	CDKindOpaqueType ContextDescriptorKind = 4 // opaque_type

	/// First kind that represents a type of any sort.
	CDKindTypeFirst = 16 // type_first

	/// This context descriptor represents a class.
	CDKindClass ContextDescriptorKind = CDKindTypeFirst // class

	/// This context descriptor represents a struct.
	CDKindStruct ContextDescriptorKind = CDKindTypeFirst + 1 // struct

	/// This context descriptor represents an enum.
	CDKindEnum ContextDescriptorKind = CDKindTypeFirst + 2 // enum

	/// Last kind that represents a type of any sort.
	CDKindTypeLast = 31 // type_last
)

// TypeReferenceKind kinds of type metadata/protocol conformance records.
type TypeReferenceKind uint8

const (
	//The conformance is for a nominal type referenced directly; getTypeDescriptor() points to the type context descriptor.
	DirectTypeDescriptor TypeReferenceKind = 0x00
	// The conformance is for a nominal type referenced indirectly; getTypeDescriptor() points to the type context descriptor.
	IndirectTypeDescriptor TypeReferenceKind = 0x01
	// The conformance is for an Objective-C class that should be looked up by class name.
	DirectObjCClassName TypeReferenceKind = 0x02
	// The conformance is for an Objective-C class that has no nominal type descriptor.
	// getIndirectObjCClass() points to a variable that contains the pointer to
	// the class object, which then requires a runtime call to get metadata.
	//
	// On platforms without Objective-C interoperability, this case is unused.
	IndirectObjCClass TypeReferenceKind = 0x03
	// We only reserve three bits for this in the various places we store it.
	FirstKind = DirectTypeDescriptor
	LastKind  = IndirectObjCClass
)

type MetadataInitializationKind uint8

const (
	// There are either no special rules for initializing the metadata or the metadata is generic.
	// (Genericity is set in the non-kind-specific descriptor flags.)
	MetadataInitNone MetadataInitializationKind = 0 // none
	//The type requires non-trivial singleton initialization using the "in-place" code pattern.
	MetadataInitSingleton MetadataInitializationKind = 1 // singleton
	// The type requires non-trivial singleton initialization using the "foreign" code pattern.
	MetadataInitForeign MetadataInitializationKind = 2 // foreign
	// We only have two bits here, so if you add a third special kind, include more flag bits in its out-of-line storage.
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

func (f TypeContextDescriptorFlags) MetadataInitialization() MetadataInitializationKind {
	return MetadataInitializationKind(types.ExtractBits(uint64(f), int32(MetadataInitialization), int32(MetadataInitialization_width)))
}
func (f TypeContextDescriptorFlags) HasImportInfo() bool {
	return types.ExtractBits(uint64(f), int32(HasImportInfo), 1) != 0
}
func (f TypeContextDescriptorFlags) HasCanonicalMetadataPrespecializations() bool {
	return types.ExtractBits(uint64(f), int32(HasCanonicalMetadataPrespecializations), 1) != 0
}
func (f TypeContextDescriptorFlags) IsActor() bool {
	return types.ExtractBits(uint64(f), int32(Class_IsActor), 1) != 0
}
func (f TypeContextDescriptorFlags) IsDefaultActor() bool {
	return types.ExtractBits(uint64(f), int32(Class_IsDefaultActor), 1) != 0
}
func (f TypeContextDescriptorFlags) ResilientSuperclassReferenceKind() TypeReferenceKind {
	return TypeReferenceKind(types.ExtractBits(uint64(f), int32(Class_ResilientSuperclassReferenceKind), int32(Class_ResilientSuperclassReferenceKind_width)))
}
func (f TypeContextDescriptorFlags) AreImmediateMembersNegative() bool {
	return types.ExtractBits(uint64(f), int32(Class_AreImmediateMembersNegative), 1) != 0
}
func (f TypeContextDescriptorFlags) HasResilientSuperclass() bool {
	return types.ExtractBits(uint64(f), int32(Class_HasResilientSuperclass), 1) != 0
}
func (f TypeContextDescriptorFlags) HasOverrideTable() bool {
	return types.ExtractBits(uint64(f), int32(Class_HasOverrideTable), 1) != 0
}
func (f TypeContextDescriptorFlags) HasVTable() bool {
	return types.ExtractBits(uint64(f), int32(Class_HasVTable), 1) != 0
}
func (f TypeContextDescriptorFlags) String() string {
	var flags []string
	if f.MetadataInitialization() != MetadataInitNone {
		flags = append(flags, fmt.Sprintf("metadata_init:%s", f.MetadataInitialization()))
	}
	if f.HasImportInfo() {
		flags = append(flags, "import_info")
	}
	if f.IsActor() {
		flags = append(flags, "actor")
	}
	if f.IsDefaultActor() {
		flags = append(flags, "default_actor")
	}
	if f.AreImmediateMembersNegative() {
		flags = append(flags, "negative_immediate_members")
	}
	if f.HasResilientSuperclass() {
		flags = append(flags, "resilient_superclass")
		flags = append(flags, fmt.Sprintf("resilient_superclass_ref:%s", f.ResilientSuperclassReferenceKind()))
	}
	if f.HasOverrideTable() {
		flags = append(flags, "override_table")
	}
	if f.HasVTable() {
		flags = append(flags, "vtable")
	}
	return strings.Join(flags, "|")
}

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
func (f ContextDescriptorFlags) KindSpecific() TypeContextDescriptorFlags {
	return TypeContextDescriptorFlags((f >> 16) & 0xFFFF)
}
func (f ContextDescriptorFlags) String() string {
	return fmt.Sprintf("kind: %s, generic: %t, unique: %t, version: %d, kind_flags: %s",
		f.Kind(),
		f.IsGeneric(),
		f.IsUnique(),
		f.Version(),
		f.KindSpecific())
}

// TargetContextDescriptor base class for all context descriptors.
type TargetContextDescriptor struct {
	Flags        ContextDescriptorFlags // Flags describing the context, including its kind and format version.
	ParentOffset RelativeDirectPointer  // The parent context, or null if this is a top-level context.
}

func (cd TargetContextDescriptor) Size() int64 {
	return int64(binary.Size(cd.Flags) + binary.Size(cd.ParentOffset.RelOff))
}

func (cd *TargetContextDescriptor) Read(r io.Reader, addr uint64) error {
	cd.ParentOffset.Address = addr + uint64(binary.Size(uint32(0)))
	if err := binary.Read(r, binary.LittleEndian, &cd.Flags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &cd.ParentOffset.RelOff); err != nil {
		return err
	}
	return nil
}

// TargetTypeContextDescriptor object
type TargetTypeContextDescriptor struct {
	TargetContextDescriptor
	NameOffset        RelativeDirectPointer // The name of the type.
	AccessFunctionPtr RelativeDirectPointer // A pointer to the metadata access function for this type.
	FieldsOffset      RelativeDirectPointer // A pointer to the field descriptor for the type, if any.
}

func (tcd TargetTypeContextDescriptor) Size() int64 {
	return tcd.TargetContextDescriptor.Size() +
		int64(binary.Size(tcd.NameOffset.RelOff)) +
		int64(binary.Size(tcd.AccessFunctionPtr.RelOff)) +
		int64(binary.Size(tcd.FieldsOffset.RelOff))
}

func (tcd *TargetTypeContextDescriptor) Read(r io.Reader, addr uint64) error {
	if err := tcd.TargetContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	addr += uint64(tcd.TargetContextDescriptor.Size())
	tcd.NameOffset.Address = addr
	tcd.AccessFunctionPtr.Address = addr + uint64(unsafe.Sizeof(RelativeDirectPointer{}.RelOff))
	tcd.FieldsOffset.Address = addr + uint64(unsafe.Sizeof(RelativeDirectPointer{}.RelOff))*2
	if err := binary.Read(r, binary.LittleEndian, &tcd.NameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &tcd.AccessFunctionPtr.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &tcd.FieldsOffset.RelOff); err != nil {
		return err
	}
	return nil
}

type TargetAnonymousContextDescriptor struct {
	TargetContextDescriptor
}

type TargetOpaqueTypeDescriptor struct {
	TargetContextDescriptor
}

type GenericContext struct {
	TargetTypeGenericContextDescriptorHeader
	Parameters   []GenericParamDescriptor
	Requirements []TargetGenericRequirementDescriptor
}

type TargetTypeGenericContextDescriptorHeader struct {
	InstantiationCache          TargetRelativeDirectPointer
	DefaultInstantiationPattern TargetRelativeDirectPointer
	Base                        TargetGenericContextDescriptorHeader
}

func (h TargetTypeGenericContextDescriptorHeader) Size() int64 {
	return int64(
		binary.Size(h.InstantiationCache.RelOff) +
			binary.Size(h.DefaultInstantiationPattern.RelOff) +
			binary.Size(h.Base),
	)
}

func (h *TargetTypeGenericContextDescriptorHeader) Read(r io.Reader, addr uint64) error {
	h.InstantiationCache.Address = addr
	h.DefaultInstantiationPattern.Address = addr + uint64(binary.Size(h.InstantiationCache.RelOff))
	if err := binary.Read(r, binary.LittleEndian, &h.InstantiationCache.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &h.DefaultInstantiationPattern.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Base); err != nil {
		return err
	}
	return nil
}

type GenericContextDescriptorFlags uint16

// HasTypePacks is whether this generic context has at least one type parameter
// pack, in which case the generic context will have a trailing
// GenericPackShapeHeader.
func (f GenericContextDescriptorFlags) HasTypePacks() bool {
	return (f & 0x01) != 0
}

// ref: include/swift/ABI/GenericContext.h
type TargetGenericContextDescriptorHeader struct {
	// The number of (source-written) generic parameters, and thus
	// the number of GenericParamDescriptors associated with this
	// context.  The parameter descriptors appear in the order in
	// which they were given in the source.
	//
	// A GenericParamDescriptor corresponds to a type metadata pointer
	// in the arguments layout when isKeyArgument() is true.
	// isKeyArgument() will be false if the parameter has been made
	// equivalent to a different parameter or a concrete type.
	NumParams uint16
	// The number of GenericRequirementDescriptors in this generic
	// signature.
	//
	// A GenericRequirementDescriptor of kind Protocol corresponds
	// to a witness table pointer in the arguments layout when
	// isKeyArgument() is true.  isKeyArgument() will be false if
	// the protocol is an Objective-C protocol.  (Unlike generic
	// parameters, redundant conformance requirements can simply be
	// eliminated, and so that case is not impossible.)
	NumRequirements uint16
	// The size of the "key" area of the argument layout, in words.
	// Key arguments include shape classes, generic parameters and
	// conformance requirements which are part of the identity of
	// the context.
	//
	// The key area of the argument layout consists of:
	//
	// - a sequence of pack lengths, in the same order as the parameter
	//   descriptors which satisfy getKind() == GenericParamKind::TypePack
	//   and hasKeyArgument();
	//
	// - a sequence of metadata or metadata pack pointers, in the same
	//   order as the parameter descriptors which satisfy hasKeyArgument();
	//
	// - a sequence of witness table or witness table pack pointers, in the
	//   same order as the requirement descriptors which satisfy
	//   hasKeyArgument().
	//
	// The elements above which are packs are precisely those appearing
	// in the sequence of trailing GenericPackShapeDescriptors.
	NumKeyArguments uint16
	// Originally this was the size of the "extra" area of the argument
	// layout, in words.  The idea was that extra arguments would
	// include generic parameters and conformances that are not part
	// of the identity of the context; however, it's unclear why we
	// would ever want such a thing.  As a result, in pre-5.8 runtimes
	// this field is always zero.  New flags can only be added as long
	// as they remains zero in code which must be compatible with
	// older Swift runtimes.
	Flags GenericContextDescriptorFlags
}

func (g TargetGenericContextDescriptorHeader) GetNumArguments() uint16 {
	return g.NumKeyArguments
}
func (g TargetGenericContextDescriptorHeader) HasArguments() bool {
	return g.GetNumArguments() > 0
}

type GenericParamKind uint8

const (
	// A type parameter.
	GPKType = 0
	// A type parameter pack.
	GPKTypePack = 1
	GPKMax      = 0x3F
)

type GenericParamDescriptor struct {
	// Don't set 0x40 for compatibility with pre-Swift 5.8 runtimes
	Value uint8
	_     [3]uint8 // alignment padding
}

func (g GenericParamDescriptor) HasKeyArgument() bool {
	return (g.Value & 0x80) != 0
}
func (g GenericParamDescriptor) GetKind() GenericParamKind {
	return GenericParamKind(g.Value & 0x3F)
}

type GenericEnvironmentFlags uint32

func (f GenericEnvironmentFlags) GetNumGenericParameterLevels() uint32 {
	return uint32(f & 0xFFF)
}
func (f GenericEnvironmentFlags) GetNumGenericRequirements() uint32 {
	return uint32((f & (0xFFFF << 12)) >> 12)
}

type TargetGenericEnvironment struct {
	Flags GenericEnvironmentFlags
}
