package swift

// __swift5_acfuncs

type AccessibleFunctionsSection struct {
	Begin uint64 // AccessibleFunctionRecord
	End   uint64 // AccessibleFunctionRecord
}

type AccessibleFunctionFlags uint32

const (
	Distributed AccessibleFunctionFlags = 0
)

type TargetAccessibleFunctionRecord struct {
	Name               int32 // char *
	GenericEnvironment int32 // TargetGenericEnvironment
	FunctionType       int32 // mangled name
	Function           int32 // void *
	Flags              AccessibleFunctionFlags
}

type AccessibleFunctionCacheEntry struct {
	Name    string
	NameLen uint32
	R       uint64 // AccessibleFunctionRecord

}

type AccessibleFunctionsState struct {
	Cache          AccessibleFunctionCacheEntry
	SectionsToScan AccessibleFunctionsSection
}
