package swift

import (
	"encoding/binary"
	"fmt"
	"io"
)

//go:generate stringer -type GenericRequirementKind,ProtocolRequirementKind -linecomment -output protocols_string.go

// ConformanceDescriptor in __TEXT.__swift5_proto
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol conformance descriptor in the __TEXT.__const section.

// Protocol swift protocol object
type Protocol struct {
	TargetProtocolDescriptor
	Address               uint64
	Name                  string
	Parent                *TargetModuleContext
	AssociatedType        string
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
			var rtyp string
			switch req.Flags.Kind() {
			case PRKindMethodc:
				rtyp = "func"
			default:
				rtyp = "var"
			}
			if !req.Flags.IsInstance() {
				rtyp = "static " + rtyp
			}
			if verbose {
				addr = " // <stripped>"
				if req.DefaultImplementation.IsSet() {
					addr = fmt.Sprintf(" // %#x", req.DefaultImplementation.GetAddress())
				}
				if req.Flags.IsSignedWithAddress() && req.Flags.ExtraDiscriminator() != 0 {
					addr += fmt.Sprintf(" __ptrauth(%#04x)", req.Flags.ExtraDiscriminator())
				}
			}
			reqs += fmt.Sprintf("    %s {%s}%s\n", rtyp, req.Flags.Kind(), addr)
		}
	}
	if verbose {
		addr = fmt.Sprintf("// %#x\n", p.Address)
	}
	return fmt.Sprintf(
		"%sprotocol %s.%s {\n%s}",
		addr,
		p.Parent.Name,
		p.Name,
		reqs,
	)
}

// TargetProtocolDescriptor
// ref: include/swift/ABI/MetadataValues.h
type TargetProtocolDescriptor struct {
	TargetContextDescriptor
	NameOffset                 RelativeDirectPointer // The name of the protocol.
	NumRequirementsInSignature uint32                // The number of generic requirements in the requirement signature of the protocol.
	NumRequirements            uint32                /* The number of requirements in the protocol. If any requirements beyond MinimumWitnessTableSizeInWords are present
	 * in the witness table template, they will be not be overwritten with defaults. */
	AssociatedTypeNamesOffset RelativeDirectPointer // Associated type names, as a space-separated list in the same order as the requirements.
}

func (d TargetProtocolDescriptor) Size() int64 {
	return int64(
		int(d.TargetContextDescriptor.Size()) +
			binary.Size(d.NameOffset.RelOff) +
			binary.Size(d.NumRequirementsInSignature) +
			binary.Size(d.NumRequirements) +
			binary.Size(d.AssociatedTypeNamesOffset.RelOff))
}

func (d *TargetProtocolDescriptor) Read(r io.Reader, addr uint64) error {
	if err := d.TargetContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	addr += uint64(d.TargetContextDescriptor.Size())
	d.NameOffset.Address = addr
	d.AssociatedTypeNamesOffset.Address = addr + uint64(binary.Size(uint32(0)*3))
	if err := binary.Read(r, binary.LittleEndian, &d.NameOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.NumRequirementsInSignature); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.NumRequirements); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.AssociatedTypeNamesOffset.RelOff); err != nil {
		return err
	}
	return nil
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

// GenericPackShapeHeader object
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

// GenericPackShapeDescriptor the GenericPackShapeHeader is followed by an array of these descriptors,
// whose length is given by the header's NumPacks field.
//
// The invariant is that all pack descriptors with GenericPackKind::Metadata
// must precede those with GenericPackKind::WitnessTable, and for each kind,
// the pack descriptors are ordered by their Index.
//
// This allows us to iterate over the generic arguments array in parallel
// with the array of pack shape descriptors. We know we have a metadata
// or witness table when we reach the generic argument whose index is
// stored in the next descriptor; we increment the descriptor pointer in this case.
//
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
	DefaultImplementation RelativeDirectPointer // The optional default implementation of the protocol.
}

func (pr TargetProtocolRequirement) Size() int64 {
	return int64(binary.Size(pr.Flags) + binary.Size(pr.DefaultImplementation.RelOff))
}

func (pr *TargetProtocolRequirement) Read(r io.Reader, addr uint64) error {
	pr.DefaultImplementation.Address = addr + uint64(binary.Size(pr.Flags))
	if err := binary.Read(r, binary.LittleEndian, &pr.Flags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &pr.DefaultImplementation.RelOff); err != nil {
		return err
	}
	return nil
}

// Descriptor in __TEXT.__swift5_protos
// This section contains an array of 32-bit signed integers.
// Each integer is a relative offset that points to a protocol descriptor in the __TEXT.__const section.

type ConformanceDescriptor struct {
	TargetProtocolConformanceDescriptor
	Address                 uint64
	Protocol                string
	TypeRef                 *Type
	Retroactive             *TargetModuleContext // context of a retroactive conformance
	ConditionalRequirements []TargetGenericRequirement
	ConditionalPackShapes   []GenericPackShapeDescriptor
	ResilientWitnesses      []ResilientWitnesses
	GenericWitnessTable     TargetGenericWitnessTable
	WitnessTablePattern     string
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
				addr = fmt.Sprintf("/* %#x */ ", witness.Implementation)
			}
			resilientWitnesses += fmt.Sprintf("    %s%s\n", addr, witness.ProtocolRequirement)
		}
	}
	var accFunc string
	if verbose {
		addr = fmt.Sprintf("// %#x\n", c.Address)
		if c.TypeRef.AccessFunction != 0 {
			accFunc = fmt.Sprintf(" // %#x", c.TypeRef.AccessFunction)
		}
	}
	var parent string
	if len(c.TypeRef.Parent.Name) > 0 {
		parent = c.TypeRef.Parent.Name + "."
	}
	return fmt.Sprintf(
		"%s"+
			"%s%s {\n"+
			"    %s %s%s%s\n"+
			"%s"+
			"%s"+
			"}",
		addr,
		c.Protocol,
		retroactive,
		c.TypeRef.Kind,
		parent,
		c.TypeRef.Name,
		accFunc,
		reqs,
		resilientWitnesses,
	)
}

// TargetProtocolConformanceDescriptor the structure of a protocol conformance.
type TargetProtocolConformanceDescriptor struct {
	ProtocolOffsest            RelativeDirectPointer // The protocol being conformed to.
	TypeRefOffsest             RelativeDirectPointer // Some description of the type that conforms to the protocol.
	WitnessTablePatternOffsest RelativeDirectPointer // The witness table pattern, which may also serve as the witness table.
	Flags                      ConformanceFlags      // Various flags, including the kind of conformance.
}

func (d TargetProtocolConformanceDescriptor) Size() int64 {
	return int64(
		binary.Size(d.ProtocolOffsest.RelOff) +
			binary.Size(d.TypeRefOffsest.RelOff) +
			binary.Size(d.WitnessTablePatternOffsest.RelOff) +
			binary.Size(d.Flags))
}

func (d *TargetProtocolConformanceDescriptor) Read(r io.Reader, addr uint64) error {
	d.ProtocolOffsest.Address = addr
	d.TypeRefOffsest.Address = addr + uint64(binary.Size(d.ProtocolOffsest.RelOff))
	d.WitnessTablePatternOffsest.Address = addr + uint64(binary.Size(d.ProtocolOffsest.RelOff))*2
	if err := binary.Read(r, binary.LittleEndian, &d.ProtocolOffsest.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.TypeRefOffsest.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.WitnessTablePatternOffsest.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.Flags); err != nil {
		return err
	}
	return nil
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

type TargetWitnessTable struct {
	Description int32
}

type ResilientWitnesses struct {
	ProtocolRequirement string
	Implementation      uint64
}

// TargetProtocolRecord the structure of a protocol reference record.
// ref: swift/ABI/Metadata.h
type TargetProtocolRecord struct {
	Protocol int32 // The protocol referenced (the remaining low bit is reserved for future use)
}

// TargetResilientWitnessesHeader a header containing information about the resilient witnesses in a protocol conformance descriptor.
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
