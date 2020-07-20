package types

import "fmt"

const (
	C_ID       = '@'
	C_CLASS    = '#'
	C_SEL      = ':'
	C_CHR      = 'c'
	C_UCHR     = 'C'
	C_SHT      = 's'
	C_USHT     = 'S'
	C_INT      = 'i'
	C_UINT     = 'I'
	C_LNG      = 'l'
	C_ULNG     = 'L'
	C_LNG_LNG  = 'q'
	C_ULNG_LNG = 'Q'
	C_FLT      = 'f'
	C_DBL      = 'd'
	C_BFLD     = 'b'
	C_BOOL     = 'B'
	C_VOID     = 'v'
	C_UNDEF    = '?'
	C_PTR      = '^'
	C_CHARPTR  = '*'
	C_ATOM     = '%'
	C_ARY_B    = '['
	C_ARY_E    = ']'
	C_UNION_B  = '('
	C_UNION_E  = ')'
	C_STRUCT_B = '{'
	C_STRUCT_E = '}'
	C_VECTOR   = '!'
	C_CONST    = 'r'
)

const IsDyldPreoptimized = 1 << 7

type ObjCInfo struct {
	SelRefCount      uint64
	ClassDefCount    uint64
	ProtocolDefCount uint64
}

type ObjCImageInfoFlag uint32

const (
	IsReplacement              ObjCImageInfoFlag = 1 << 0 // used for Fix&Continue, now ignored
	SupportsGC                 ObjCImageInfoFlag = 1 << 1 // image supports GC
	RequiresGC                 ObjCImageInfoFlag = 1 << 2 // image requires GC
	OptimizedByDyld            ObjCImageInfoFlag = 1 << 3 // image is from an optimized shared cache
	CorrectedSynthesize        ObjCImageInfoFlag = 1 << 4 // used for an old workaround, now ignored
	IsSimulated                ObjCImageInfoFlag = 1 << 5 // image compiled for a simulator platform
	HasCategoryClassProperties ObjCImageInfoFlag = 1 << 6 // New ABI: category_t.classProperties fields are present, Old ABI: Set by some compilers. Not used by the runtime.
	OptimizedByDyldClosure     ObjCImageInfoFlag = 1 << 7 // dyld (not the shared cache) optimized this.

	// 1 byte Swift unstable ABI version number
	SwiftUnstableVersionMaskShift = 8
	SwiftUnstableVersionMask      = 0xff << SwiftUnstableVersionMaskShift

	// 2 byte Swift stable ABI version number
	SwiftStableVersionMaskShift = 16
	SwiftStableVersionMask      = 0xffff << SwiftStableVersionMaskShift
)

func (f ObjCImageInfoFlag) SwiftVersion() string {
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

type ObjCImageInfo struct {
	Version uint32
	Flags   ObjCImageInfoFlag

	// DyldPreoptimized uint32
}

type MLFlags uint32

const (
	METHOD_LIST_FLAGS_MASK         = 3
	METHOD_LIST_IS_UNIQUED MLFlags = 1
	METHOD_LIST_FIXED_UP   MLFlags = 3
)

type MethodListType struct {
	EntSizeAndFlags uint32
	Count           uint32
	// Space   uint32
	// MethodArrayBase uint64
}

func (ml MethodListType) IsUniqued() bool {
	return MLFlags(ml.EntSizeAndFlags&METHOD_LIST_FLAGS_MASK)&METHOD_LIST_IS_UNIQUED != 0
}
func (ml MethodListType) FixedUp() bool {
	return MLFlags(ml.EntSizeAndFlags)&METHOD_LIST_FLAGS_MASK == METHOD_LIST_FIXED_UP
}
func (ml MethodListType) EntSize() uint32 {
	return ml.EntSizeAndFlags & 0xfffc
}

type MethodType struct {
	NameVMAddr  uint64 // SEL
	TypesVMAddr uint64 // const char *
	ImpVMAddr   uint64 // IMP
}

type Method2Type struct {
	NameOffset  uint32 // SEL
	TypesOffset uint32 // const char *
	ImpOffset   uint32 // IMP
}

type ObjCMethod struct {
	NameVMAddr  uint64 // & SEL
	TypesVMAddr uint64 // & const char *
	ImpVMAddr   uint64 // & IMP

	// We also need to know where the reference to the nameVMAddr was
	// This is so that we know how to rebind that location
	NameLocationVMAddr uint64
	Name               string
	Types              string
	Pointer            FilePointer
}

type ObjCPropertyListType struct {
	EntSize uint32
	Count   uint32
}

type ObjCPropertyType struct {
	NameVMAddr       uint64
	AttributesVMAddr uint64
}

type ObjCProperty struct {
	ObjCPropertyType
	Name       string
	Attributes string
}

type ObjCCategoryType struct {
	NameVMAddr               uint64
	ClsVMAddr                uint64
	InstanceMethodsVMAddr    uint64
	ClassMethodsVMAddr       uint64
	ProtocolsVMAddr          uint64
	InstancePropertiesVMAddr uint64
}

type ObjCCategory struct {
	Name string
	ObjCCategoryType
}

const (
	// Values for protocol_t->flags
	PROTOCOL_FIXED_UP_2   = (1 << 31) // must never be set by compiler
	PROTOCOL_FIXED_UP_1   = (1 << 30) // must never be set by compiler
	PROTOCOL_IS_CANONICAL = (1 << 29) // must never be set by compiler
	// Bits 0..15 are reserved for Swift's use.
	PROTOCOL_FIXED_UP_MASK = (PROTOCOL_FIXED_UP_1 | PROTOCOL_FIXED_UP_2)
)

type ProtocolType struct {
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

type ObjCProtocol struct {
	Name                    string
	InstanceMethods         []ObjCMethod
	InstanceProperties      []ObjCProperty
	ClassMethods            []ObjCMethod
	OptionalInstanceMethods []ObjCMethod
	OptionalClassMethods    []ObjCMethod
	ExtendedMethodTypes     string
	DemangledName           string
	ProtocolType
}

func (p *ObjCProtocol) String() string {
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

type ObjCClass struct {
	Name                  string
	SuperClass            *ObjCClass
	InstanceMethods       []ObjCMethod
	Ivars                 []ObjCIvar
	ClassPtr              FilePointer
	IsaVmAddr             uint64
	SuperclassVmAddr      uint64
	MethodCacheBuckets    uint64
	MethodCacheProperties uint64
	DataVMAddr            uint64
	IsSwiftLegacy         bool
	IsSwiftStable         bool
	ReadOnlyData          ClassRO64Type
}

func (c *ObjCClass) String() string {
	iMethods := "  // instance methods\n"
	for _, meth := range c.InstanceMethods {
		iMethods += fmt.Sprintf("  0x%011x -[%s %s]\n", meth.Pointer.Offset, c.Name, meth.Name)
	}
	if len(c.InstanceMethods) == 0 {
		iMethods = ""
	}
	subClass := "<ROOT>"
	if c.SuperClass != nil {
		subClass = c.SuperClass.Name
	}
	return fmt.Sprintf(
		"0x%011x %s : %s\n"+
			"%s",
		c.ClassPtr.Offset,
		c.Name,
		subClass,
		iMethods,
	)
}

type ObjcClassType struct {
	IsaVmAddr              uint32
	SuperclassVmAddr       uint32
	MethodCacheBuckets     uint32
	MethodCacheProperties  uint32
	DataVmAddrAndFastFlags uint32
}

type SwiftClassMetadata struct {
	ObjcClassType
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

type ClassROType struct {
	Flags                ClassRoFlags
	InstanceStart        uint32
	InstanceSize         uint32
	_                    uint32
	IvarLayoutVmAddr     uint32
	NameVmAddr           uint32
	BaseMethodsVmAddr    uint32
	BaseProtocolsVmAddr  uint32
	IvarsVmAddr          uint32
	WeakIvarLayoutVmAddr uint32
	BasePropertiesVmAddr uint32
}

type ObjcClass64Type struct {
	IsaVmAddr              uint64
	SuperclassVmAddr       uint64
	MethodCacheBuckets     uint64
	MethodCacheProperties  uint64
	DataVmAddrAndFastFlags uint64
}

type SwiftClassMetadata64 struct {
	ObjcClass64Type
	SwiftClassFlags uint64
}

type ClassRO64Type struct {
	Flags         ClassRoFlags
	InstanceStart uint32
	InstanceSize  uint64
	// _                    uint32
	IvarLayoutVmAddr     uint64
	NameVmAddr           uint64
	BaseMethodsVmAddr    uint64
	BaseProtocolsVmAddr  uint64
	IvarsVmAddr          uint64
	WeakIvarLayoutVmAddr uint64
	BasePropertiesVmAddr uint64
}

type ObjCIvarListType struct {
	EntSize uint32
	Count   uint32
}

type ObjCIvarType struct {
	Offset      uint64 // uint32_t*  (uint64_t* on x86_64)
	NameVMAddr  uint64 // const char*
	TypesVMAddr uint64 // const char*
	Alignment   uint32
	Size        uint32
}

type ObjCIvar struct {
	Name string
	Type string
	ObjCIvarType
}
