package objc

import (
	"fmt"

	"github.com/blacktop/go-macho/types"
)

const IsDyldPreoptimized = 1 << 7

type Info struct {
	SelRefCount      uint64
	ClassDefCount    uint64
	ProtocolDefCount uint64
}

func (i Info) String() string {
	return fmt.Sprintf(
		"ObjC Info\n"+
			"=========\n"+
			"ClassDefs    = %d\n"+
			"ProtocolDefs = %d\n"+
			"SelRefs      = %d\n",
		i.ClassDefCount,
		i.ProtocolDefCount,
		i.SelRefCount,
	)
}

type ImageInfoFlag uint32

const (
	IsReplacement              ImageInfoFlag = 1 << 0 // used for Fix&Continue, now ignored
	SupportsGC                 ImageInfoFlag = 1 << 1 // image supports GC
	RequiresGC                 ImageInfoFlag = 1 << 2 // image requires GC
	OptimizedByDyld            ImageInfoFlag = 1 << 3 // image is from an optimized shared cache
	CorrectedSynthesize        ImageInfoFlag = 1 << 4 // used for an old workaround, now ignored
	IsSimulated                ImageInfoFlag = 1 << 5 // image compiled for a simulator platform
	HasCategoryClassProperties ImageInfoFlag = 1 << 6 // New ABI: category_t.classProperties fields are present, Old ABI: Set by some compilers. Not used by the runtime.
	OptimizedByDyldClosure     ImageInfoFlag = 1 << 7 // dyld (not the shared cache) optimized this.

	// 1 byte Swift unstable ABI version number
	SwiftUnstableVersionMaskShift = 8
	SwiftUnstableVersionMask      = 0xff << SwiftUnstableVersionMaskShift

	// 2 byte Swift stable ABI version number
	SwiftStableVersionMaskShift = 16
	SwiftStableVersionMask      = 0xffff << SwiftStableVersionMaskShift
)

func (f ImageInfoFlag) SwiftVersion() string {
	// TODO: I noticed there is some flags higher than swift version (Console has 84019008, which is a version of 0x502)
	swiftVersion := (f >> 8) & 0xff
	if swiftVersion != 0 {
		switch swiftVersion {
		case 1:
			return "Swift 1.0"
		case 2:
			return "Swift 1.1"
		case 3:
			return "Swift 2.0"
		case 4:
			return "Swift 3.0"
		case 5:
			return "Swift 4.0"
		case 6:
			return "Swift 4.1/4.2"
		case 7:
			return "Swift 5 or later"
		default:
			return fmt.Sprintf("Unknown future Swift version: %d", swiftVersion)
		}
	}
	return "not swift"
}

type ImageInfo struct {
	Version uint32
	Flags   ImageInfoFlag

	// DyldPreoptimized uint32
}

type MLFlags uint32

const (
	METHOD_LIST_FLAGS_MASK uint32  = 0xffff0003
	METHOD_LIST_IS_UNIQUED MLFlags = 1
	METHOD_LIST_FIXED_UP   MLFlags = 3
	METHOD_LIST_SMALL              = 0x80000000
)

type MethodList struct {
	EntSizeAndFlags uint32
	Count           uint32
	// Space           uint32
	// MethodArrayBase uint64
}

func (ml MethodList) IsUniqued() bool {
	return MLFlags(ml.EntSizeAndFlags&METHOD_LIST_FLAGS_MASK)&METHOD_LIST_IS_UNIQUED == 1
}
func (ml MethodList) FixedUp() bool {
	return MLFlags(ml.EntSizeAndFlags&METHOD_LIST_FLAGS_MASK)&METHOD_LIST_FIXED_UP == 1
}
func (ml MethodList) IsSmall() bool {
	return ml.EntSizeAndFlags&METHOD_LIST_SMALL == METHOD_LIST_SMALL
}
func (ml MethodList) EntSize() uint32 {
	return ml.EntSizeAndFlags & ^METHOD_LIST_FLAGS_MASK
}
func (ml MethodList) String() string {
	return fmt.Sprintf("entrysize=0x%08x, fixed_up=%t, uniqued=%t, small=%t", ml.EntSize(), ml.FixedUp(), ml.IsUniqued(), ml.IsSmall())
}

type MethodT struct {
	NameVMAddr  uint64 // SEL
	TypesVMAddr uint64 // const char *
	ImpVMAddr   uint64 // IMP
}

type MethodSmallT struct {
	NameOffset  int32 // SEL
	TypesOffset int32 // const char *
	ImpOffset   int32 // IMP
}

type Method struct {
	NameVMAddr  uint64 // & SEL
	TypesVMAddr uint64 // & const char *
	ImpVMAddr   uint64 // & IMP

	// We also need to know where the reference to the nameVMAddr was
	// This is so that we know how to rebind that location
	NameLocationVMAddr uint64
	Name               string
	Types              string
	Pointer            types.FilePointer
}

func (m *Method) NumberOfArguments() int {
	if m == nil {
		return 0
	}
	return getNumberOfArguments(m.Types)
}

func (m *Method) ReturnType() string {
	return getReturnType(m.Types)
}

// func (m *Method) ArgumentType(index int) string {
// 	return getArgumentType(m.Types, index)
// }

type PropertyList struct {
	EntSize uint32
	Count   uint32
}

type PropertyT struct {
	NameVMAddr       uint64
	AttributesVMAddr uint64
}

type Property struct {
	PropertyT
	Name       string
	Attributes string
}

type CategoryT struct {
	NameVMAddr               uint64
	ClsVMAddr                uint64
	InstanceMethodsVMAddr    uint64
	ClassMethodsVMAddr       uint64
	ProtocolsVMAddr          uint64
	InstancePropertiesVMAddr uint64
}

type Category struct {
	Name string
	CategoryT
}

const (
	// Values for protocol_t->flags
	PROTOCOL_FIXED_UP_2   = (1 << 31) // must never be set by compiler
	PROTOCOL_FIXED_UP_1   = (1 << 30) // must never be set by compiler
	PROTOCOL_IS_CANONICAL = (1 << 29) // must never be set by compiler
	// Bits 0..15 are reserved for Swift's use.
	PROTOCOL_FIXED_UP_MASK = (PROTOCOL_FIXED_UP_1 | PROTOCOL_FIXED_UP_2)
)

type ProtocolT struct {
	IsaVMAddr                     uint64
	NameVMAddr                    uint64
	ProtocolsVMAddr               uint64
	InstanceMethodsVMAddr         uint64
	ClassMethodsVMAddr            uint64
	OptionalInstanceMethodsVMAddr uint64
	OptionalClassMethodsVMAddr    uint64
	InstancePropertiesVMAddr      uint64
	Size                          uint32
	Flags                         uint32
	// Fields below this point are not always present on disk.
	ExtendedMethodTypesVMAddr uint64
	DemangledNameVMAddr       uint64
	ClassPropertiesVMAddr     uint64
}

type Protocol struct {
	Name                    string
	InstanceMethods         []Method
	InstanceProperties      []Property
	ClassMethods            []Method
	OptionalInstanceMethods []Method
	OptionalClassMethods    []Method
	ExtendedMethodTypes     string
	DemangledName           string
	ProtocolT
}

func (p *Protocol) String() string {
	var props string
	for _, prop := range p.InstanceProperties {
		props += fmt.Sprintf(" @property %s\n", prop.Name)
	}
	iMethods := "  // instance methods\n"
	for _, meth := range p.InstanceMethods {
		iMethods += fmt.Sprintf(" -[%s %s]\n", p.Name, meth.Name)
	}
	if len(p.InstanceMethods) == 0 {
		iMethods = ""
	}
	optMethods := "  // instance methods\n"
	for _, meth := range p.OptionalInstanceMethods {
		optMethods += fmt.Sprintf(" -[%s %s]\n", p.Name, meth.Name)
	}
	if len(p.InstanceMethods) == 0 {
		optMethods = ""
	}
	return fmt.Sprintf(
		"@protocol %s\n"+
			"%s"+
			"\n%s"+
			"\n@optional\n"+
			"%s"+
			"@end\n",
		p.Name,
		props,
		iMethods,
		optMethods,
	)
}

const (
	FAST_DATA_MASK   = 0xfffffffc
	FAST_DATA_MASK64 = 0x00007ffffffffff8
)

const (
	FAST_IS_SWIFT_LEGACY = 0x1 // < 5
	FAST_IS_SWIFT_STABLE = 0x2 // 5.X

	IsSwiftPreStableABI = 0x1
)

type Class struct {
	Name                  string
	SuperClass            *Class
	InstanceMethods       []Method
	Ivars                 []Ivar
	ClassPtr              types.FilePointer
	IsaVMAddr             uint64
	SuperclassVMAddr      uint64
	MethodCacheBuckets    uint64
	MethodCacheProperties uint64
	DataVMAddr            uint64
	IsSwiftLegacy         bool
	IsSwiftStable         bool
	ReadOnlyData          ClassRO64
}

func (c *Class) String() string {

	iMethods := "  // instance methods\n"
	for _, meth := range c.InstanceMethods {
		iMethods += fmt.Sprintf("  0x%011x -[%s %s]\n", meth.Pointer.VMAdder, c.Name, meth.Name)
	}
	if len(c.InstanceMethods) == 0 {
		iMethods = ""
	}
	var subClass string
	if c.ReadOnlyData.Flags.IsRoot() {
		subClass = "<ROOT>"
	}
	if c.SuperClass != nil {
		subClass = c.SuperClass.Name
	}
	return fmt.Sprintf(
		"0x%011x %s : %s\n"+
			"%s",
		c.ClassPtr.VMAdder,
		c.Name,
		subClass,
		iMethods,
	)
}

type ObjcClassT struct {
	IsaVMAddr              uint32
	SuperclassVMAddr       uint32
	MethodCacheBuckets     uint32
	MethodCacheProperties  uint32
	DataVMAddrAndFastFlags uint32
}

type SwiftClassMetadata struct {
	ObjcClassT
	SwiftClassFlags uint32
}

type ClassRoFlags uint32

const (
	// class is a metaclass
	RO_META ClassRoFlags = (1 << 0)
	// class is a root class
	RO_ROOT ClassRoFlags = (1 << 1)
	// class has .cxx_construct/destruct implementations
	RO_HAS_CXX_STRUCTORS ClassRoFlags = (1 << 2)
	// class has +load implementation
	RO_HAS_LOAD_METHOD ClassRoFlags = (1 << 3)
	// class has visibility=hidden set
	RO_HIDDEN ClassRoFlags = (1 << 4)
	// class has attributeClassRoFlags = (objc_exception): OBJC_EHTYPE_$_ThisClass is non-weak
	RO_EXCEPTION ClassRoFlags = (1 << 5)
	// class has ro field for Swift metadata initializer callback
	RO_HAS_SWIFT_INITIALIZER ClassRoFlags = (1 << 6)
	// class compiled with ARC
	RO_IS_ARC ClassRoFlags = (1 << 7)
	// class has .cxx_destruct but no .cxx_construct ClassRoFlags = (with RO_HAS_CXX_STRUCTORS)
	RO_HAS_CXX_DTOR_ONLY ClassRoFlags = (1 << 8)
	// class is not ARC but has ARC-style weak ivar layout
	RO_HAS_WEAK_WITHOUT_ARC ClassRoFlags = (1 << 9)
	// class does not allow associated objects on instances
	RO_FORBIDS_ASSOCIATED_OBJECTS ClassRoFlags = (1 << 10)
	// class is in an unloadable bundle - must never be set by compiler
	RO_FROM_BUNDLE ClassRoFlags = (1 << 29)
	// class is unrealized future class - must never be set by compiler
	RO_FUTURE ClassRoFlags = (1 << 30)
	// class is realized - must never be set by compiler
	RO_REALIZED ClassRoFlags = (1 << 31)
)

func (f ClassRoFlags) IsMeta() bool {
	return f&RO_META != 0
}
func (f ClassRoFlags) IsRoot() bool {
	return f&RO_ROOT != 0
}
func (f ClassRoFlags) HasCxxStructors() bool {
	return f&RO_HAS_CXX_STRUCTORS != 0
}

type ClassRO struct {
	Flags                ClassRoFlags
	InstanceStart        uint32
	InstanceSize         uint32
	_                    uint32
	IvarLayoutVMAddr     uint32
	NameVMAddr           uint32
	BaseMethodsVMAddr    uint32
	BaseProtocolsVMAddr  uint32
	IvarsVMAddr          uint32
	WeakIvarLayoutVMAddr uint32
	BasePropertiesVMAddr uint32
}

type ObjcClass64 struct {
	IsaVMAddr              uint64
	SuperclassVMAddr       uint64
	MethodCacheBuckets     uint64
	MethodCacheProperties  uint64
	DataVMAddrAndFastFlags uint64
}

type SwiftClassMetadata64 struct {
	ObjcClass64
	SwiftClassFlags uint64
}

type ClassRO64 struct {
	Flags         ClassRoFlags
	InstanceStart uint32
	InstanceSize  uint64
	// _                    uint32
	IvarLayoutVMAddr     uint64
	NameVMAddr           uint64
	BaseMethodsVMAddr    uint64
	BaseProtocolsVMAddr  uint64
	IvarsVMAddr          uint64
	WeakIvarLayoutVMAddr uint64
	BasePropertiesVMAddr uint64
}

type IvarList struct {
	EntSize uint32
	Count   uint32
}

type IvarT struct {
	Offset      uint64 // uint32_t*  (uint64_t* on x86_64)
	NameVMAddr  uint64 // const char*
	TypesVMAddr uint64 // const char*
	Alignment   uint32
	Size        uint32
}

type Ivar struct {
	Name string
	Type string
	IvarT
}