package swift

import "fmt"

//go:generate stringer -type NecessaryBindingsKind -output capture_string.go

// __TEXT.__swift5_capture
// Capture descriptors describe the layout of a closure context object.
// Unlike nominal types, the generic substitutions for a closure context come from the object, and not the metadata.

type Capture struct {
	CaptureDescriptor
	Address         uint64
	CaptureTypes    []string
	MetadataSources []MetadataSource
	Bindings        []NecessaryBindings
}

func (c Capture) String() string {
	var captureTypes string
	if len(c.CaptureTypes) > 0 {
		captureTypes += "\t/* capture types */\n"
		for _, t := range c.CaptureTypes {
			captureTypes += fmt.Sprintf("\t%s\n", t)
		}
	}
	var metadataSources string
	if len(c.MetadataSources) > 0 {
		metadataSources += "\t/* metadata sources */\n"
		for _, m := range c.MetadataSources {
			metadataSources += fmt.Sprintf("\t%s: %s\n", m.MangledType, m.MangledMetadataSource)
		}
	}
	var bindings string
	if len(c.Bindings) > 0 {
		bindings += "\t/* necessary bindings */\n"
		for _, b := range c.Bindings {
			bindings += fmt.Sprintf("\t// Kind: %d, RequirementsSet: %d, RequirementsVector: %d, Conformances: %d\n", b.Kind, b.RequirementsSet, b.RequirementsVector, b.Conformances)
		}
	}
	return fmt.Sprintf(
		"block /* %#x */ {\n"+
			"%s"+
			"%s"+
			"%s"+
			"}",
		c.Address,
		captureTypes,
		metadataSources,
		bindings,
	)
}

// CaptureDescriptor describe the layout of a closure context
// object. Unlike nominal types, the generic substitutions for a
// closure context come from the object, and not the metadata.
// ref: include/swift/RemoteInspection/Records.h - CaptureDescriptor
type CaptureDescriptor struct {
	NumCaptureTypes    uint32 // The number of captures in the closure and the number of typerefs that immediately follow this struct.
	NumMetadataSources uint32 // The number of sources of metadata available in the MetadataSourceMap directly following the list of capture's typerefs.
	NumBindings        uint32 // The number of items in the NecessaryBindings structure at the head of the closure.
}

type CaptureTypeRecord struct {
	MangledTypeName int32
}

type MetadataSourceRecord struct {
	MangledTypeName       int32
	MangledMetadataSource int32
}

type MetadataSource struct {
	MangledType           string
	MangledMetadataSource string
}

type NecessaryBindingsKind uint32

const (
	PartialApply NecessaryBindingsKind = iota
	AsyncFunction
)

type NecessaryBindings struct {
	Kind               NecessaryBindingsKind
	RequirementsSet    int32
	RequirementsVector int32
	Conformances       int32
}
