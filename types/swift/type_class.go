package swift

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type TargetClassDescriptor struct {
	TargetTypeContextDescriptor
	SuperclassType                                       RelativeDirectPointer
	MetadataNegativeSizeInWordsORResilientMetadataBounds uint32
	MetadataPositiveSizeInWordsORExtraClassFlags         uint32
	NumImmediateMembers                                  uint32
	NumFields                                            uint32
	FieldOffsetVectorOffset                              uint32
}

func (tcd TargetClassDescriptor) Size() int64 {
	return int64(
		int(tcd.TargetTypeContextDescriptor.Size()) +
			binary.Size(tcd.SuperclassType.RelOff) +
			binary.Size(tcd.MetadataNegativeSizeInWordsORResilientMetadataBounds) +
			binary.Size(tcd.MetadataPositiveSizeInWordsORExtraClassFlags) +
			binary.Size(tcd.NumImmediateMembers) +
			binary.Size(tcd.NumFields) +
			binary.Size(tcd.FieldOffsetVectorOffset))
}

func (c *TargetClassDescriptor) Read(r io.Reader, addr uint64) error {
	if err := c.TargetTypeContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	c.SuperclassType.Address = addr + uint64(c.TargetTypeContextDescriptor.Size())
	if err := binary.Read(r, binary.LittleEndian, &c.SuperclassType.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.MetadataNegativeSizeInWordsORResilientMetadataBounds); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.MetadataPositiveSizeInWordsORExtraClassFlags); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.NumImmediateMembers); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.NumFields); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &c.FieldOffsetVectorOffset); err != nil {
		return err
	}
	return nil
}

type ExtraClassDescriptorFlags uint32

const (
	HasObjCResilientClassStub ExtraClassDescriptorFlags = 0
)

type TargetOverrideTableHeader struct {
	NumEntries uint32
}

type TargetMethodOverrideDescriptor struct {
	Class  int32
	Method int32
	Impl   int32
}

type TargetResilientSuperclass struct {
	Superclass int32
}

type TargetObjCResilientClassStubInfo struct {
	Stub int32 // Objective-C class stub.
}

type TargetSingletonMetadataInitialization struct {
	InitializationCacheOffset TargetRelativeDirectPointer // The initialization cache. Out-of-line because mutable.
	IncompleteMetadata        TargetRelativeDirectPointer // UNION: The incomplete metadata, for structs, enums and classes without resilient ancestry.
	// ResilientPattern
	// If the class descriptor's hasResilientSuperclass() flag is set,
	// this field instead points at a pattern used to allocate and
	// initialize metadata for this class, since it's size and contents
	// is not known at compile time.
	CompletionFunction TargetRelativeDirectPointer // The completion function. The pattern will always be null, even for a resilient class.
}

func (s TargetSingletonMetadataInitialization) Size() int64 {
	return int64(
		binary.Size(s.InitializationCacheOffset.RelOff) +
			binary.Size(s.IncompleteMetadata.RelOff) +
			binary.Size(s.CompletionFunction.RelOff))
}

func (s *TargetSingletonMetadataInitialization) Read(r io.Reader, addr uint64) error {
	s.InitializationCacheOffset.Address = addr
	s.IncompleteMetadata.Address = addr + uint64(binary.Size(s.InitializationCacheOffset.RelOff))
	s.CompletionFunction.Address = addr + uint64(binary.Size(s.InitializationCacheOffset.RelOff)*2)
	if err := binary.Read(r, binary.LittleEndian, &s.InitializationCacheOffset.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &s.IncompleteMetadata.RelOff); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &s.CompletionFunction.RelOff); err != nil {
		return err
	}
	return nil
}

// TargetForeignMetadataInitialization is the control structure for performing non-trivial initialization of
// singleton foreign metadata.
type TargetForeignMetadataInitialization struct {
	CompletionFunction RelativeDirectPointer // The completion function. The pattern will always be null.
}

func (f TargetForeignMetadataInitialization) Size() int64 {
	return int64(binary.Size(f.CompletionFunction.RelOff))
}

func (f *TargetForeignMetadataInitialization) Read(r io.Reader, addr uint64) error {
	f.CompletionFunction.Address = addr
	return binary.Read(r, binary.LittleEndian, &f.CompletionFunction.RelOff)
}

type VTable struct {
	TargetVTableDescriptorHeader
	MethodListAddr int64
	Methods        []Method
}

type TargetVTableDescriptorHeader struct {
	VTableOffset uint32
	VTableSize   uint32
}

type Method struct {
	TargetMethodDescriptor
	Address uint64
	Symbol  string
}

type TargetMethodDescriptor struct {
	Flags MethodDescriptorFlags
	Impl  int32
}

type MDKind uint8

const (
	MDKMethod MDKind = iota
	MDKInit
	MDKGetter
	MDKSetter
	MDKModifyCoroutine
	MDKReadCoroutine
)

func (md MDKind) String() string {
	switch md {
	case MDKMethod:
		return "method"
	case MDKInit:
		return "init"
	case MDKGetter:
		return "getter"
	case MDKSetter:
		return "setter"
	case MDKModifyCoroutine:
		return "modify"
	case MDKReadCoroutine:
		return "read"
	default:
		return fmt.Sprintf("unknown kind %d", md)
	}
}

type MethodDescriptorFlags uint32

const (
	KindMask                = 0x0F // 16 kinds should be enough for anybody
	IsInstanceMask          = 0x10
	IsDynamicMask           = 0x20
	IsAsyncMask             = 0x40
	ExtraDiscriminatorShift = 16
	ExtraDiscriminatorMask  = 0xFFFF0000
)

func (f MethodDescriptorFlags) Kind() MDKind {
	return MDKind(f & KindMask)
}
func (f MethodDescriptorFlags) IsInstance() bool {
	return (f & IsInstanceMask) != 0
}
func (f MethodDescriptorFlags) IsDynamic() bool {
	return (f & IsDynamicMask) != 0
}
func (f MethodDescriptorFlags) IsAsync() bool {
	return (f & IsAsyncMask) != 0
}
func (f MethodDescriptorFlags) ExtraDiscriminator() uint16 {
	return uint16(f >> ExtraDiscriminatorShift)
}
func (f MethodDescriptorFlags) String(field string) string {
	var flags []string
	if f.IsInstance() {
		flags = append(flags, "instance")
	}
	if f.IsDynamic() {
		flags = append(flags, "dynamic")
	}
	if f.IsAsync() {
		flags = append(flags, "async")
	}
	if f.ExtraDiscriminator() != 0 {
		flags = append(flags, fmt.Sprintf("extra discriminator %#x", f.ExtraDiscriminator()))
	}
	if len(strings.Join(flags, "|")) == 0 {
		return f.Kind().String()
	}
	if len(field) > 0 {
		field += " "
	}
	return fmt.Sprintf("%s%s (%s)", field, f.Kind(), strings.Join(flags, "|"))
}
