package swift

import "fmt"

// __TEXT.__swift5_builtin
// This section contains an array of builtin type descriptors.
// A builtin type descriptor describes the basic layout information about any builtin types referenced from other sections.

const MaxNumExtraInhabitants = 0x7FFFFFFF

// BuiltinType builtin swift type
type BuiltinType struct {
	BuiltinTypeDescriptor
	Address uint64
	Name    string
}

func (b BuiltinType) String() string {
	return b.dump(false)
}
func (b BuiltinType) Verbose() string {
	return b.dump(true)
}
func (b BuiltinType) dump(verbose bool) string {
	var numExtraInhabitants string
	if b.NumExtraInhabitants == MaxNumExtraInhabitants {
		numExtraInhabitants = "max"
	} else {
		numExtraInhabitants = fmt.Sprintf("%d", b.NumExtraInhabitants)
	}
	var addr string
	if verbose {
		addr = fmt.Sprintf("// %#x\n", b.Address)
	}
	return fmt.Sprintf(
		"%s%s\t// "+
			"(size: %d"+
			", align: %d"+
			", bitwise-takable: %t"+
			", stride: %d"+
			", extra-inhabitants: %s)",
		addr,
		b.Name,
		b.Size,
		b.AlignmentAndFlags.Alignment(),
		b.AlignmentAndFlags.IsBitwiseTakable(),
		b.Stride,
		numExtraInhabitants)
}

// BuiltinTypeDescriptor type records describe basic layout information about any builtin types referenced from the other sections.
// ref: include/swift/RemoteInspection/Records.h
type BuiltinTypeDescriptor struct {
	TypeName            int32
	Size                uint32
	AlignmentAndFlags   builtinTypeFlag
	Stride              uint32
	NumExtraInhabitants uint32
}

type builtinTypeFlag uint32

func (f builtinTypeFlag) IsBitwiseTakable() bool {
	return ((f >> 16) & 1) != 0
}
func (f builtinTypeFlag) Alignment() uint16 {
	return uint16(f & 0xffff)
}
