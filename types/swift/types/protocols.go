package types

import (
	"fmt"
)

//go:generate stringer -type GenericRequirementKind,ProtocolRequirementKind -linecomment -output protocols_string.go

// Protocol swift protocol object
type Protocol struct {
	Header                TargetProtocolDescriptor
	Address               uint64
	Name                  string
	AssociatedType        string
	Parent                string
	SignatureRequirements []TargetGenericRequirement
	Requirements          []TargetProtocolRequirement
}

func (p Protocol) String() string {
	return p.dump(false)
}
func (p Protocol) Verbose() string {
	return p.dump(true)
}
func (p Protocol) dump(verbose bool) string {
	var addr string
	var reqs string
	if len(p.Requirements) > 0 {
		reqs = "  /* requirements */\n"
		for _, req := range p.Requirements {
			if verbose && req.DefaultImplementation != 0 {
				addr = fmt.Sprintf(" // %#x", req.DefaultImplementation)
			}
			reqs += fmt.Sprintf("    %s%s\n", req.Flags, addr)
		}
	}
	if verbose {
		addr = fmt.Sprintf("// %#x\n", p.Address)
	}
	return fmt.Sprintf(
		"%sprotocol %s {\n%s}",
		addr,
		p.Name,
		reqs,
	)
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

type GenericRequirementKind uint8

const (
	GRKindProtocol  GenericRequirementKind = 0 // protocol
	GRKindSameType  GenericRequirementKind = 1 // same-type
	GRKindBaseClass GenericRequirementKind = 2 // base class
	// implied by a same-type or base-class constraint that binds a parameter with protocol requirements.
	GRKindSameConformance GenericRequirementKind = 3    // same-conformance
	GRKindLayout          GenericRequirementKind = 0x1F // layout
)

type GenericRequirementFlags uint32

func (f GenericRequirementFlags) HasKeyArgument() bool {
	return (f & 0x80) != 0
}
func (f GenericRequirementFlags) HasExtraArgument() bool {
	return (f & 0x40) != 0
}
func (f GenericRequirementFlags) Kind() GenericRequirementKind {
	return GenericRequirementKind(f & 0x1F)
}
func (f GenericRequirementFlags) String() string {
	return fmt.Sprintf("key_arg: %t, extra_arg: %t, kind: %s", f.HasKeyArgument(), f.HasExtraArgument(), f.Kind())
}

// ref: swift/ABI/Metadata.h - TargetGenericRequirementDescriptor
type TargetGenericRequirementDescriptor struct {
	Flags                               GenericRequirementFlags
	Param                               int32 // The type that's constrained, described as a mangled name.
	TypeOrProtocolOrConformanceOrLayout int32 // UNION: flags determine type
}

type TargetGenericRequirement struct {
	Name string
	Kind string
	TargetGenericRequirementDescriptor
}

// ref: swift/ABI/GenericContext.h - GenericPackShapeHeader
type GenericPackShapeHeader struct {
	NumPacks        uint16 // The number of generic parameters and conformance requirements which are packs.
	NumShapeClasses uint16 // The number of equivalence classes in the same-shape relation.
}
type GenericPackKind uint16

const (
	Metadata     GenericPackKind = 0
	WitnessTable GenericPackKind = 1
)

// ref: swift/ABI/GenericContext.h - GenericPackShapeDescriptor
type GenericPackShapeDescriptor struct {
	Kind       GenericPackKind
	Index      uint16 // The index of this metadata pack or witness table pack in the generic arguments array.
	ShapeClass uint16 // The equivalence class of this pack under the same-shape relation.
	_          uint16 // Unused
}

const (
	// Bit used to indicate that an associated type witness is a pointer to a mangled name (vs. a pointer to metadata).
	AssociatedTypeMangledNameBit uint32 = 0x01
	// Prefix byte used to identify an associated type whose mangled name is relative to the protocol's context rather than the conforming type's context.
	AssociatedTypeInProtocolContextByte uint8 = 0xFF
)

type ProtocolRequirementKind uint8

const (
	PRKindBaseProtocol                        ProtocolRequirementKind = iota // base protocol
	PRKindMethodc                                                            // method
	PRKindInit                                                               // initializer
	PRKindGetter                                                             // getter
	PRKindSetter                                                             // setter
	PRKindReadCoroutine                                                      // read coroutine
	PRKindModifyCoroutine                                                    // modify coroutine
	PRKindAssociatedTypeAccessFunction                                       // associated type access function
	PRKindAssociatedConformanceAccessFunction                                // associated conformance access function
)

type ProtocolRequirementFlags uint32

func (f ProtocolRequirementFlags) Kind() ProtocolRequirementKind {
	return ProtocolRequirementKind(f & 0x0F)
}
func (f ProtocolRequirementFlags) IsInstance() bool {
	return (f & 0x10) != 0
}
func (f ProtocolRequirementFlags) IsAsync() bool {
	return (f & 0x20) != 0
}
func (f ProtocolRequirementFlags) IsSignedWithAddress() bool {
	return f.Kind() != PRKindBaseProtocol
}
func (f ProtocolRequirementFlags) ExtraDiscriminator() uint16 {
	return uint16(f >> 16)
}
func (f ProtocolRequirementFlags) IsFunctionImpl() bool {
	switch f.Kind() {
	case PRKindMethodc, PRKindInit, PRKindGetter, PRKindSetter, PRKindReadCoroutine, PRKindModifyCoroutine:
		return !f.IsAsync()
	default:
		return false
	}
}
func (f ProtocolRequirementFlags) String() string {
	return fmt.Sprintf("kind: %s, instance: %t, async: %t, signed_with_addr: %t, extra_discriminator: %x, function_impl: %t",
		f.Kind(),
		f.IsInstance(),
		f.IsAsync(),
		f.IsSignedWithAddress(),
		f.ExtraDiscriminator(),
		f.IsFunctionImpl())
}

// TargetProtocolRequirement protocol requirement descriptor. This describes a single protocol requirement in a protocol descriptor.
// The index of the requirement in the descriptor determines the offset of the witness in a witness table for this protocol.
// ref: swift/ABI/Metadata.h - TargetProtocolRequirement
type TargetProtocolRequirement struct {
	Flags                 ProtocolRequirementFlags
	DefaultImplementation int32 // The optional default implementation of the protocol.
}

type ConformanceFlags uint32

const (
	UnusedLowBits ConformanceFlags = 0x07 // historical conformance kind

	TypeMetadataKindMask  ConformanceFlags = 0x7 << 3 // 8 type reference kinds
	TypeMetadataKindShift                  = 3

	IsRetroactiveMask          ConformanceFlags = 0x01 << 6
	IsSynthesizedNonUniqueMask ConformanceFlags = 0x01 << 7

	NumConditionalRequirementsMask  ConformanceFlags = 0xFF << 8
	NumConditionalRequirementsShift                  = 8

	HasResilientWitnessesMask  ConformanceFlags = 0x01 << 16
	HasGenericWitnessTableMask ConformanceFlags = 0x01 << 17

	NumConditionalPackDescriptorsMask  ConformanceFlags = 0xFF << 24
	NumConditionalPackDescriptorsShift                  = 24
)

// IsRetroactive Is the conformance "retroactive"?
//
// A conformance is retroactive when it occurs in a module that is
// neither the module in which the protocol is defined nor the module
// in which the conforming type is defined. With retroactive conformance,
// it is possible to detect a conflict at run time.
func (f ConformanceFlags) IsRetroactive() bool {
	return (f & IsRetroactiveMask) != 0
}

// IsSynthesizedNonUnique is the conformance synthesized in a non-unique manner?
//
// The Swift compiler will synthesize conformances on behalf of some
// imported entities (e.g., C typedefs with the swift_wrapper attribute).
// Such conformances are retroactive by nature, but the presence of multiple
// such conformances is not a conflict because all synthesized conformances
// will be equivalent.
func (f ConformanceFlags) IsSynthesizedNonUnique() bool {
	return (f & IsSynthesizedNonUniqueMask) != 0
}

// GetNumConditionalRequirements retrieve the # of conditional requirements.
func (f ConformanceFlags) GetNumConditionalRequirements() int {
	return int((f & NumConditionalRequirementsMask) >> NumConditionalRequirementsShift)
}

// HasResilientWitnesses whether this conformance has any resilient witnesses.
func (f ConformanceFlags) HasResilientWitnesses() bool {
	return (f & HasResilientWitnessesMask) != 0
}

// HasGenericWitnessTable whether this conformance has a generic witness table that may need to
// be instantiated.
func (f ConformanceFlags) HasGenericWitnessTable() bool {
	return (f & HasGenericWitnessTableMask) != 0
}

// NumConditionalPackShapeDescriptors retrieve the # of conditional pack shape descriptors.
func (f ConformanceFlags) NumConditionalPackShapeDescriptors() int {
	return int((f & NumConditionalPackDescriptorsMask) >> NumConditionalPackDescriptorsShift)
}

// GetTypeReferenceKind retrieve the type reference kind kind.
func (f ConformanceFlags) GetTypeReferenceKind() TypeReferenceKind {
	return TypeReferenceKind((f & TypeMetadataKindMask) >> TypeMetadataKindShift)
}

func (f ConformanceFlags) String() string {
	return fmt.Sprintf("retroactive: %t, synthesized_nonunique: %t, num_cond_reqs: %d, has_resilient_witnesses: %t, has_generic_witness_table: %t, num_cond_pack_shape_desc: %d, type_reference_kind: %s",
		f.IsRetroactive(),
		f.IsSynthesizedNonUnique(),
		f.GetNumConditionalRequirements(),
		f.HasResilientWitnesses(),
		f.HasGenericWitnessTable(),
		f.NumConditionalPackShapeDescriptors(),
		f.GetTypeReferenceKind(),
	)
}

// ConformanceDescriptor in __TEXT.__swift5_proto
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol conformance descriptor in the __TEXT.__const section.

type TargetProtocolConformanceDescriptor struct {
	ProtocolOffsest            int32            // The protocol being conformed to.
	TypeRefOffsest             int32            // Some description of the type that conforms to the protocol.
	WitnessTablePatternOffsest int32            // The witness table pattern, which may also serve as the witness table.
	Flags                      ConformanceFlags // Various flags, including the kind of conformance.
}

type ConformanceDescriptor struct {
	TargetProtocolConformanceDescriptor
	Address                 uint64
	Protocol                string
	TypeRef                 *TypeDescriptor
	Retroactive             *TargetModuleContext // context of a retroactive conformance
	ConditionalRequirements []TargetGenericRequirement
	ResilientWitnesses      []ResilientWitnesses
	GenericWitnessTable     TargetGenericWitnessTable
}

func (c ConformanceDescriptor) String() string {
	return c.dump(false)
}
func (c ConformanceDescriptor) Verbose() string {
	return c.dump(true)
}
func (c ConformanceDescriptor) dump(verbose bool) string {
	var addr string
	var retroactive string
	if c.Flags.IsRetroactive() {
		retroactive = fmt.Sprintf(": %s", c.Retroactive.Name)
	}
	var reqs string
	if len(c.ConditionalRequirements) > 0 {
		reqs = "\n  /* conditional requirements */\n"
		for _, req := range c.ConditionalRequirements {
			reqs += fmt.Sprintf("    %s: %s\n", req.Name, req.Kind)
		}
	}
	var resilientWitnesses string
	if len(c.ResilientWitnesses) > 0 {
		resilientWitnesses = "\n  /* resilient witnesses */\n"
		for _, witness := range c.ResilientWitnesses {
			if verbose {
				addr = fmt.Sprintf("\t// %#x", witness.Implementation)
			}
			resilientWitnesses += fmt.Sprintf("    %s%s\n", witness.ProtocolRequirement, addr)
		}
	}
	if verbose {
		addr = fmt.Sprintf("// %#x\n", c.Address)
	}
	return fmt.Sprintf(
		"%s"+
			"%s%s {\n"+
			"    %s %s.%s // %#x\n"+
			"%s"+
			"%s"+
			"}",
		addr,
		c.Protocol,
		retroactive,
		c.TypeRef.Kind,
		c.TypeRef.Parent.Name,
		c.TypeRef.Name,
		c.TypeRef.AccessFunction,
		reqs,
		resilientWitnesses,
	)
}

type TargetWitnessTable struct {
	Description int32
}

type ResilientWitnesses struct {
	ProtocolRequirement string
	Implementation      uint64
}

// TargetResilientWitnessesHeader object
// ref: swift/ABI/Metadata.h - TargetResilientWitnessesHeader
type TargetResilientWitnessesHeader struct {
	NumWitnesses uint32
}

// TargetResilientWitness object
// ref: swift/ABI/Metadata.h - TargetResilientWitness
type TargetResilientWitness struct {
	Requirement uint32
	Impl        int32
}

// TargetGenericWitnessTable object
// ref: swift/ABI/Metadata.h - TargetGenericWitnessTable
type TargetGenericWitnessTable struct {
	WitnessTableSizeInWords                                uint16
	WitnessTablePrivateSizeInWordsAndRequiresInstantiation uint16
	Instantiator                                           int32
	PrivateData                                            int32
}
