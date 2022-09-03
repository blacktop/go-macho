package protocols

import (
	"fmt"

	"github.com/blacktop/go-macho/types/swift/types"
)

// Protocol swift protocol object
type Protocol struct {
	Name           string
	AssociatedType string
	Parent         *Protocol
	Descriptor
}

func (p Protocol) String() string {
	var associateType string
	if p.Descriptor.AssociatedTypeNamesOffset != 0 {
		associateType = fmt.Sprintf("AssociatedType: %s\n", p.AssociatedType)
	}
	var parent string
	if p.Descriptor.ParentOffset != 0 {
		parent = fmt.Sprintf("\n---\nParent %s\n", p.Parent)
	}
	return fmt.Sprintf(
		"Name:           %s\n"+
			"%s"+
			"%s%s",
		p.Name, associateType, p.Descriptor, parent)
}

// ProtocolContextDescriptorFlags flags for protocol context descriptors.
// These values are used as the kindSpecificFlags of the ContextDescriptorFlags for the protocol.
type ProtocolContextDescriptorFlags uint16

const (
	/// Whether this protocol is class-constrained.
	HasClassConstraint       ProtocolContextDescriptorFlags = 0
	HasClassConstraint_width ProtocolContextDescriptorFlags = 1

	/// Whether this protocol is resilient.
	IsResilient ProtocolContextDescriptorFlags = 1

	/// Special protocol value.
	SpecialProtocolKind       ProtocolContextDescriptorFlags = 2
	SpecialProtocolKind_width ProtocolContextDescriptorFlags = 6
)

// Descriptor in __TEXT.__swift5_protos
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol descriptor in the __TEXT.__const section.
type Descriptor struct {
	Flags                      types.ContextDescriptorFlags // overide kind specific flags w/ ProtocolContextDescriptorFlags TODO: handle kind specific flags
	ParentOffset               int32
	NameOffset                 int32  // The name of the protocol.
	NumRequirementsInSignature uint32 // The number of generic requirements in the requirement signature of the protocol.
	NumRequirements            uint32 /* The number of requirements in the protocol. If any requirements beyond MinimumWitnessTableSizeInWords are present
	 * in the witness table template, they will be not be overwritten with defaults. */
	AssociatedTypeNamesOffset int32 // Associated type names, as a space-separated list in the same order as the requirements.
}

func (d Descriptor) GetProtocolContextDescriptorFlags() ProtocolContextDescriptorFlags {
	return ProtocolContextDescriptorFlags(d.Flags.KindSpecificFlags())
}

func (d Descriptor) String() string {
	return fmt.Sprintf(
		"Flags: (%s)\n"+
			"NumRequirementsInSignature: %d\n"+
			"NumRequirements:            %d",
		d.Flags, d.NumRequirementsInSignature, d.NumRequirements)
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
type CDType struct {
	ProtocolDescriptorOffset int32
	TypeRefOffset            int32
	WitnessTableOffset       int32
	Flags                    conformanceFlag
}

type ConformanceDescriptor struct {
	Protocol     string
	TypeRef      int32
	WitnessTable int32
	CDType
}
