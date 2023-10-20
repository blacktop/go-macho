package swift

import "io"

// Flags for anonymous type context descriptors. These values are used as the
// kindSpecificFlags of the ContextDescriptorFlags for the anonymous context.
type AnonymousContextDescriptorFlags uint16

const (
	// Whether this anonymous context descriptor is followed by its
	// mangled name, which can be used to match the descriptor at runtime.
	HasMangledName AnonymousContextDescriptorFlags = 0
)

type Anonymous struct {
	TargetAnonymousContextDescriptor
	GenericContext     *GenericContext
	MangledContextName string
}

type TargetAnonymousContextDescriptor struct {
	TargetContextDescriptor
}

func (tacd TargetAnonymousContextDescriptor) Size() int64 {
	return tacd.TargetContextDescriptor.Size()
}

func (tacd *TargetAnonymousContextDescriptor) Read(r io.Reader, addr uint64) error {
	if err := tacd.TargetContextDescriptor.Read(r, addr); err != nil {
		return err
	}
	return nil
}
