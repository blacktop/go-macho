package types

type ObjCInfo struct {
	SelRefCount      uint64
	ClassDefCount    uint64
	ProtocolDefCount uint64
}

const IsDyldPreoptimized = 1 << 7

type ObjCImageInfo struct {
	Version uint32
	Flags   uint32

	// DyldPreoptimized uint32
}

type MethodList_t struct {
	EntSize uint32
	Count   uint32
	// MethodArrayBase uint64
}

type Method_t struct {
	NameVMAddr  uint64 // SEL
	TypesVMAddr uint64 // const char *
	ImpVMAddr   uint64 // IMP
}

type ObjCMethod struct {
	NameVMAddr  uint64 // & SEL
	TypesVMAddr uint64 // & const char *
	ImpVMAddr   uint64 // & IMP

	// We also need to know where the reference to the nameVMAddr was
	// This is so that we know how to rebind that location
	NameLocationVMAddr uint64
	Name               string
}

type ObjCCategory struct {
	NameVMAddr               uint64
	ClsVMAddr                uint64
	InstanceMethodsVMAddr    uint64
	ClassMethodsVMAddr       uint64
	ProtocolsVMAddr          uint64
	InstancePropertiesVMAddr uint64
}

type ObjCProtocol struct {
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

type ClassRO struct {
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

type ClassRO64 struct {
	Flags                uint32
	InstanceStart        uint32
	InstanceSize         uint32
	_                    uint64
	IvarLayoutVmAddr     uint64
	NameVmAddr           uint64
	BaseMethodsVmAddr    uint64
	BaseProtocolsVmAddr  uint64
	IvarsVmAddr          uint64
	WeakIvarLayoutVmAddr uint64
	BasePropertiesVmAddr uint64
}

const (
	FAST_DATA_MASK   = 0xfffffffc
	FAST_DATA_MASK64 = 0x00007ffffffffff8
)

type ObjcClass struct {
	IsaVmAddr              uint32
	SuperclassVmAddr       uint32
	MethodCacheBuckets     uint32
	MethodCacheProperties  uint32
	DataVmAddrAndFastFlags uint32
}

type SwiftClassMetadata struct {
	ObjcClass
	SwiftClassFlags uint32
}

type ObjcClass64 struct {
	IsaVmAddr              uint64
	SuperclassVmAddr       uint64
	MethodCacheBuckets     uint64
	MethodCacheProperties  uint64
	DataVmAddrAndFastFlags uint64
}

type SwiftClassMetadata64 struct {
	ObjcClass64
	SwiftClassFlags uint64
}
