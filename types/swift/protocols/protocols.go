package protocols

// Protocol swift protocol object
type Protocol struct {
	Name   string
	Parent *Protocol
	Descriptor
}

// Descriptor in __TEXT.__swift5_protos
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol descriptor in the __TEXT.__const section.
type Descriptor struct {
	Flags                      uint32
	Parent                     int32
	Name                       int32
	NumRequirementsInSignature uint32
	NumRequirements            uint32
	AssociatedTypeNames        int32
}

type TargetGenericRequirementDescriptor struct {
	Flags uint32
}

type conformanceFlag uint32

const (
	UnusedLowBits conformanceFlag = 0x07 // historical conformance kind

	TypeMetadataKindMask  conformanceFlag = 0x7 << 3 // 8 type reference kinds
	TypeMetadataKindShift conformanceFlag = 3

	IsRetroactiveMask          conformanceFlag = 0x01 << 6
	IsSynthesizedNonUniqueMask conformanceFlag = 0x01 << 7

	NumConditionalRequirementsMask  conformanceFlag = 0xFF << 8
	NumConditionalRequirementsShift conformanceFlag = 8

	HasResilientWitnessesMask  conformanceFlag = 0x01 << 16
	HasGenericWitnessTableMask conformanceFlag = 0x01 << 17
)

// Kinds of type metadata/protocol conformance records.
type referenceKind uint32

const (
	// The conformance is for a nominal type referenced directly;
	// getTypeDescriptor() points to the type context descriptor.
	DirectTypeDescriptor referenceKind = 0x00

	// The conformance is for a nominal type referenced indirectly;
	// getTypeDescriptor() points to the type context descriptor.
	IndirectTypeDescriptor referenceKind = 0x01

	// The conformance is for an Objective-C class that should be looked up
	// by class name.
	DirectObjCClassName referenceKind = 0x02

	// The conformance is for an Objective-C class that has no nominal type
	// descriptor.
	// getIndirectObjCClass() points to a variable that contains the pointer to
	// the class object, which then requires a runtime call to get metadata.
	//
	// On platforms without Objective-C interoperability, this case is
	// unused.
	IndirectObjCClass referenceKind = 0x03

	// We only reserve three bits for this in the various places we store it.

	// First_Kind = DirectTypeDescriptor
	// Last_Kind  = IndirectObjCClass
)

// IsRetroactive Is the conformance "retroactive"?
//
// A conformance is retroactive when it occurs in a module that is
// neither the module in which the protocol is defined nor the module
// in which the conforming type is defined. With retroactive conformance,
// it is possible to detect a conflict at run time.
func (f conformanceFlag) IsRetroactive() bool {
	return f&IsRetroactiveMask != 0
}

// IsSynthesizedNonUnique is the conformance synthesized in a non-unique manner?
//
// The Swift compiler will synthesize conformances on behalf of some
// imported entities (e.g., C typedefs with the swift_wrapper attribute).
// Such conformances are retroactive by nature, but the presence of multiple
// such conformances is not a conflict because all synthesized conformances
// will be equivalent.
func (f conformanceFlag) IsSynthesizedNonUnique() bool {
	return f&IsSynthesizedNonUniqueMask != 0
}

// GetNumConditionalRequirements retrieve the # of conditional requirements.
func (f conformanceFlag) GetNumConditionalRequirements() int {
	return int((f & NumConditionalRequirementsMask) >> NumConditionalRequirementsShift)
}

// HasResilientWitnesses whether this conformance has any resilient witnesses.
func (f conformanceFlag) HasResilientWitnesses() bool {
	return f&HasResilientWitnessesMask != 0
}

// HasGenericWitnessTable whether this conformance has a generic witness table that may need to
// be instantiated.
func (f conformanceFlag) HasGenericWitnessTable() bool {
	return f&HasGenericWitnessTableMask != 0
}

// GetTypeReferenceKind retrieve the type reference kind kind.
func (f conformanceFlag) GetTypeReferenceKind() referenceKind {
	return referenceKind((f & TypeMetadataKindMask) >> TypeMetadataKindShift)
}

// ConformanceDescriptor in __TEXT.__swift5_proto
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol conformance descriptor in the __TEXT.__const section.
type ConformanceDescriptor struct {
	ProtocolDescriptor    int32
	NominalTypeDescriptor int32
	ProtocolWitnessTable  int32
	ConformanceFlags      conformanceFlag
}
