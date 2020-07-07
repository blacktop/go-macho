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

type ObjCImageInfo struct {
	Version uint32
	Flags   uint32

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

type ObjCPropertyListT struct {
	EntSize uint32
	Count   uint32
}

type ObjCPropertyT struct {
	NameVMAddr       uint64
	AttributesVMAddr uint64
}

type ObjCProperty struct {
	ObjCPropertyT
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

type ClassROType struct {
	Flags                uint32
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
	Flags         uint32
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
