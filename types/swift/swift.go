package swift

// credit: https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html

const (
	/// The name of the standard library, which is a reserved module name.
	STDLIB_NAME = "Swift"
	/// The name of the Onone support library, which is a reserved module name.
	SWIFT_ONONE_SUPPORT = "SwiftOnoneSupport"
	/// The name of the SwiftShims module, which contains private stdlib decls.
	SWIFT_SHIMS_NAME = "SwiftShims"
	/// The name of the Builtin module, which contains Builtin functions.
	BUILTIN_NAME = "Builtin"
	/// The name of the clang imported header module.
	CLANG_HEADER_MODULE_NAME = "__ObjC"
	/// The prefix of module names used by LLDB to capture Swift expressions
	LLDB_EXPRESSIONS_MODULE_NAME_PREFIX = "__lldb_expr_"

	/// The name of the fake module used to hold imported Objective-C things.
	MANGLING_MODULE_OBJC = "__C"
	/// The name of the fake module used to hold synthesized ClangImporter things.
	MANGLING_MODULE_CLANG_IMPORTER = "__C_Synthesized"

	/// The name prefix for C++ template instantiation imported as a Swift struct.
	CXX_TEMPLATE_INST_PREFIX = "__CxxTemplateInst"

	SEMANTICS_PROGRAMTERMINATION_POINT = "programtermination_point"

	/// The name of the Builtin type prefix
	BUILTIN_TYPE_NAME_PREFIX = "Builtin."
)

const (
	/// The name of the Builtin type for Int
	BUILTIN_TYPE_NAME_INT = "Builtin.Int"
	/// The name of the Builtin type for Int8
	BUILTIN_TYPE_NAME_INT8 = "Builtin.Int8"
	/// The name of the Builtin type for Int16
	BUILTIN_TYPE_NAME_INT16 = "Builtin.Int16"
	/// The name of the Builtin type for Int32
	BUILTIN_TYPE_NAME_INT32 = "Builtin.Int32"
	/// The name of the Builtin type for Int64
	BUILTIN_TYPE_NAME_INT64 = "Builtin.Int64"
	/// The name of the Builtin type for Int128
	BUILTIN_TYPE_NAME_INT128 = "Builtin.Int128"
	/// The name of the Builtin type for Int256
	BUILTIN_TYPE_NAME_INT256 = "Builtin.Int256"
	/// The name of the Builtin type for Int512
	BUILTIN_TYPE_NAME_INT512 = "Builtin.Int512"
	/// The name of the Builtin type for IntLiteral
	BUILTIN_TYPE_NAME_INTLITERAL = "Builtin.IntLiteral"
	/// The name of the Builtin type for IEEE Floating point types.
	BUILTIN_TYPE_NAME_FLOAT = "Builtin.FPIEEE"
	// The name of the builtin type for power pc specific floating point types.
	BUILTIN_TYPE_NAME_FLOAT_PPC = "Builtin.FPPPC"
	/// The name of the Builtin type for NativeObject
	BUILTIN_TYPE_NAME_NATIVEOBJECT = "Builtin.NativeObject"
	/// The name of the Builtin type for BridgeObject
	BUILTIN_TYPE_NAME_BRIDGEOBJECT = "Builtin.BridgeObject"
	/// The name of the Builtin type for RawPointer
	BUILTIN_TYPE_NAME_RAWPOINTER = "Builtin.RawPointer"
	/// The name of the Builtin type for UnsafeValueBuffer
	BUILTIN_TYPE_NAME_UNSAFEVALUEBUFFER = "Builtin.UnsafeValueBuffer"
	/// The name of the Builtin type for UnknownObject
	///
	/// This no longer exists as an AST-accessible type, but it's still used for
	/// fields shaped like AnyObject when ObjC interop is enabled.
	BUILTIN_TYPE_NAME_UNKNOWNOBJECT = "Builtin.UnknownObject"
	/// The name of the Builtin type for Vector
	BUILTIN_TYPE_NAME_VEC = "Builtin.Vec"
	/// The name of the Builtin type for SILToken
	BUILTIN_TYPE_NAME_SILTOKEN = "Builtin.SILToken"
	/// The name of the Builtin type for Word
	BUILTIN_TYPE_NAME_WORD = "Builtin.Word"
)

// __TEXT.__swift5_assocty
// This section contains an array of associated type descriptors.
// An associated type descriptor contains a collection of associated type records for a conformance.
// An associated type records describe the mapping from an associated type to the type witness of a conformance.

type AssociatedTypeRecord struct {
	Name                int32
	SubstitutedTypeName int32
}

type AssociatedTypeDescriptorHeader struct {
	ConformingTypeName       int32
	ProtocolTypeName         int32
	NumAssociatedTypes       uint32
	AssociatedTypeRecordSize uint32
}
type AssociatedTypeDescriptor struct {
	AssociatedTypeDescriptorHeader
	AssociatedTypeRecords []AssociatedTypeRecord
}

// __TEXT.__swift5_builtin
// This section contains an array of builtin type descriptors.
// A builtin type descriptor describes the basic layout information about any builtin types referenced from other sections.

type BuiltinTypeFlag uint32

func (f BuiltinTypeFlag) IsBitwiseTakable() bool {
	return (f>>16)&1 != 0
}
func (f BuiltinTypeFlag) Alignment() uint16 {
	return uint16(f & 0xffff)
}

type BuiltinTypeDescriptor struct {
	TypeName            int32
	Size                uint32
	AlignmentAndFlags   BuiltinTypeFlag
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

type CaptureDescriptorHeader struct {
	NumCaptureTypes    uint32
	NumMetadataSources uint32
	NumBindings        uint32
}

type CaptureDescriptor struct {
	CaptureDescriptorHeader
	CaptureTypeRecords    []CaptureTypeRecord
	MetadataSourceRecords []MetadataSourceRecord
}

// __TEXT.__swift5_replac
// This section contains dynamic replacement information.
// This is essentially the Swift equivalent of Objective-C method swizzling.

type Replacement struct {
	ReplacedFunctionKey int32
	NewFunction         int32
	Replacement         int32
	Flags               uint32
}

type ReplacementScope struct {
	Flags           uint32
	NumReplacements uint32
}

type AutomaticReplacements struct {
	Flags           uint32
	NumReplacements uint32 // hard coded to 1
	Replacements    int32
}

// __TEXT.__swift5_replac2
// This section contains dynamica replacement information for opaque types.

type Replacement2 struct {
	Original    int32
	Replacement int32
}

type AutomaticReplacementsSome struct {
	Flags           uint32
	NumReplacements uint32
	Replacements    []Replacement
}
