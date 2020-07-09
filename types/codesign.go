package types

type CsMagic uint32

const (
	// Magic numbers used by Code Signing
	CSMAGIC_REQUIREMENT               CsMagic = 0xfade0c00 // single Requirement blob
	CSMAGIC_REQUIREMENTS              CsMagic = 0xfade0c01 // Requirements vector (internal requirements)
	CSMAGIC_CODEDIRECTORY             CsMagic = 0xfade0c02 // CodeDirectory blob
	CSMAGIC_EMBEDDED_SIGNATURE        CsMagic = 0xfade0cc0 // embedded form of signature data
	CSMAGIC_EMBEDDED_SIGNATURE_OLD    CsMagic = 0xfade0b02 /* XXX */
	CSMAGIC_LIBRARY_DEPENDENCY_BLOB   CsMagic = 0xfade0c05
	CSMAGIC_EMBEDDED_ENTITLEMENTS     CsMagic = 0xfade7171 /* embedded entitlements */
	CSMAGIC_EMBEDDED_ENTITLEMENTS_DER CsMagic = 0xfade7172 /* embedded entitlements */
	CSMAGIC_DETACHED_SIGNATURE        CsMagic = 0xfade0cc1 // multi-arch collection of embedded signatures
	CSMAGIC_BLOBWRAPPER               CsMagic = 0xfade0b01 // used for the cms blob
)

var csMagicStrings = []intName{
	{uint32(CSMAGIC_REQUIREMENT), "Requirement"},
	{uint32(CSMAGIC_REQUIREMENTS), "Requirements"},
	{uint32(CSMAGIC_CODEDIRECTORY), "Codedirectory"},
	{uint32(CSMAGIC_EMBEDDED_SIGNATURE), "Embedded Signature"},
	{uint32(CSMAGIC_EMBEDDED_SIGNATURE_OLD), "Embedded Signature (Old)"},
	{uint32(CSMAGIC_EMBEDDED_ENTITLEMENTS), "Embedded Entitlements"},
	{uint32(CSMAGIC_DETACHED_SIGNATURE), "Detached Signature"},
	{uint32(CSMAGIC_BLOBWRAPPER), "Blob Wrapper"},
}

func (cm CsMagic) String() string   { return stringName(uint32(cm), csMagicStrings, false) }
func (cm CsMagic) GoString() string { return stringName(uint32(cm), csMagicStrings, true) }

type CsHashType uint8

const (
	CS_PAGE_SIZE = 4096

	CS_HASHTYPE_NOHASH           CsHashType = 0
	CS_HASHTYPE_SHA1             CsHashType = 1
	CS_HASHTYPE_SHA256           CsHashType = 2
	CS_HASHTYPE_SHA256_TRUNCATED CsHashType = 3
	CS_HASHTYPE_SHA384           CsHashType = 4
	CS_HASHTYPE_SHA512           CsHashType = 5

	CS_HASH_SIZE_SHA1             = 20
	CS_HASH_SIZE_SHA256           = 32
	CS_HASH_SIZE_SHA256_TRUNCATED = 20

	CS_CDHASH_LEN    = 20 /* always - larger hashes are truncated */
	CS_HASH_MAX_SIZE = 48 /* max size of the hash we'll support */
)

var csHashTypeStrings = []intName{
	{uint32(CS_HASHTYPE_NOHASH), "No Hash"},
	{uint32(CS_HASHTYPE_SHA1), "Sha1"},
	{uint32(CS_HASHTYPE_SHA256), "Sha256"},
	{uint32(CS_HASHTYPE_SHA256_TRUNCATED), "Sha256 (Truncated)"},
	{uint32(CS_HASHTYPE_SHA384), "Sha384"},
	{uint32(CS_HASHTYPE_SHA512), "Sha512"},
}

func (c CsHashType) String() string   { return stringName(uint32(c), csHashTypeStrings, false) }
func (c CsHashType) GoString() string { return stringName(uint32(c), csHashTypeStrings, true) }

const (
	/*
	 * Currently only to support Legacy VPN plugins, and Mac App Store
	 * but intended to replace all the various platform code, dev code etc. bits.
	 */
	CS_SIGNER_TYPE_UNKNOWN       = 0
	CS_SIGNER_TYPE_LEGACYVPN     = 5
	CS_SIGNER_TYPE_MAC_APP_STORE = 6

	CS_SUPPL_SIGNER_TYPE_UNKNOWN    = 0
	CS_SUPPL_SIGNER_TYPE_TRUSTCACHE = 7
	CS_SUPPL_SIGNER_TYPE_LOCAL      = 8

	CSTYPE_INDEX_REQUIREMENTS = 0x00000002 /* compat with amfi */
	CSTYPE_INDEX_ENTITLEMENTS = 0x00000005 /* compat with amfi */

	kSecCodeSignatureAdhoc = 2
)

type CsSlotType uint32

const (
	CSSLOT_CODEDIRECTORY                 CsSlotType = 0
	CSSLOT_INFOSLOT                      CsSlotType = 1
	CSSLOT_REQUIREMENTS                  CsSlotType = 2
	CSSLOT_RESOURCEDIR                   CsSlotType = 3
	CSSLOT_APPLICATION                   CsSlotType = 4
	CSSLOT_ENTITLEMENTS                  CsSlotType = 5
	CSSLOT_ALTERNATE_CODEDIRECTORIES     CsSlotType = 0x1000
	CSSLOT_ALTERNATE_CODEDIRECTORY_MAX              = 5
	CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT            = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX
	CSSLOT_CMS_SIGNATURE                 CsSlotType = 0x10000
	CSSLOT_IDENTIFICATIONSLOT            CsSlotType = 0x10001
	CSSLOT_TICKETSLOT                    CsSlotType = 0x10002
)

var csSlotTypeStrings = []intName{
	{uint32(CSSLOT_CODEDIRECTORY), "CodeDirectory"},
	{uint32(CSSLOT_INFOSLOT), "InfoSlot"},
	{uint32(CSSLOT_REQUIREMENTS), "Requirements"},
	{uint32(CSSLOT_RESOURCEDIR), "ResourceDir"},
	{uint32(CSSLOT_APPLICATION), "Application"},
	{uint32(CSSLOT_ENTITLEMENTS), "Entitlements"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORIES), "AlternateCodeDirectories"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORY_MAX), "AlternateCodeDirectoryMax"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT), "AlternateCodeDirectoryLimit"},
	{uint32(CSSLOT_CMS_SIGNATURE), "CMS (RFC3852) signature"},
	{uint32(CSSLOT_IDENTIFICATIONSLOT), "IdentificationSlot"},
	{uint32(CSSLOT_TICKETSLOT), "TicketSlot"},
}

func (c CsSlotType) String() string {
	return stringName(uint32(c), csSlotTypeStrings, false)
}
func (c CsSlotType) GoString() string {
	return stringName(uint32(c), csSlotTypeStrings, true)
}

// RequirementTypes
type CsRequirementType uint32

const (
	HostRequirementType       CsRequirementType = 1 /* what hosts may run us */
	GuestRequirementType      CsRequirementType = 2 /* what guests we may run */
	DesignatedRequirementType CsRequirementType = 3 /* designated requirement */
	LibraryRequirementType    CsRequirementType = 4 /* what libraries we may link against */
	PluginRequirementType     CsRequirementType = 5 /* what plug-ins we may load */
)

var csRequirementTypeStrings = []intName{
	{uint32(HostRequirementType), "Host Requirement"},
	{uint32(GuestRequirementType), "Guest Requirement"},
	{uint32(DesignatedRequirementType), "Designated Requirement"},
	{uint32(LibraryRequirementType), "Library Requirement"},
	{uint32(PluginRequirementType), "Plugin Requirement"},
}

func (cm CsRequirementType) String() string {
	return stringName(uint32(cm), csRequirementTypeStrings, false)
}
func (cm CsRequirementType) GoString() string {
	return stringName(uint32(cm), csRequirementTypeStrings, true)
}

// Structure of a SuperBlob
type CsBlobIndex struct {
	Type   CsSlotType // type of entry
	Offset uint32     // offset of entry
}

type CsSuperBlob struct {
	Magic  CsMagic // magic number
	Length uint32  // total length of SuperBlob
	Count  uint32  // number of index entries following
	// Index  []CsBlobIndex // (count) entries
	// followed by Blobs in no particular order as indicated by offsets in index
}

type CDVersion uint32

const (
	CS_SUPPORTS_SCATTER     CDVersion = 0x20100
	CS_SUPPORTS_TEAMID      CDVersion = 0x20200
	CS_SUPPORTS_CODELIMIT64 CDVersion = 0x20300
	CS_SUPPORTS_EXECSEG     CDVersion = 0x20400
	CS_SUPPORTS_RUNTIME     CDVersion = 0x20500
	CS_SUPPORTS_LINKAGE     CDVersion = 0x20600
)

type CsCodeDirectoryFlag uint32

const (
	/* code signing attributes of a process */
	CS_VALID          CsCodeDirectoryFlag = 0x00000001 /* dynamically valid */
	CS_ADHOC          CsCodeDirectoryFlag = 0x00000002 /* ad hoc signed */
	CS_GET_TASK_ALLOW CsCodeDirectoryFlag = 0x00000004 /* has get-task-allow entitlement */
	CS_INSTALLER      CsCodeDirectoryFlag = 0x00000008 /* has installer entitlement */

	CS_FORCED_LV       CsCodeDirectoryFlag = 0x00000010 /* Library Validation required by Hardened System Policy */
	CS_INVALID_ALLOWED CsCodeDirectoryFlag = 0x00000020 /* (macOS Only) Page invalidation allowed by task port policy */

	CS_HARD             CsCodeDirectoryFlag = 0x00000100 /* don't load invalid pages */
	CS_KILL             CsCodeDirectoryFlag = 0x00000200 /* kill process if it becomes invalid */
	CS_CHECK_EXPIRATION CsCodeDirectoryFlag = 0x00000400 /* force expiration checking */
	CS_RESTRICT         CsCodeDirectoryFlag = 0x00000800 /* tell dyld to treat restricted */

	CS_ENFORCEMENT            CsCodeDirectoryFlag = 0x00001000 /* require enforcement */
	CS_REQUIRE_LV             CsCodeDirectoryFlag = 0x00002000 /* require library validation */
	CS_ENTITLEMENTS_VALIDATED CsCodeDirectoryFlag = 0x00004000 /* code signature permits restricted entitlements */
	CS_NVRAM_UNRESTRICTED     CsCodeDirectoryFlag = 0x00008000 /* has com.apple.rootless.restricted-nvram-variables.heritable entitlement */

	CS_RUNTIME CsCodeDirectoryFlag = 0x00010000 /* Apply hardened runtime policies */

	CS_ALLOWED_MACHO CsCodeDirectoryFlag = (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME)

	CS_EXEC_SET_HARD        CsCodeDirectoryFlag = 0x00100000 /* set CS_HARD on any exec'ed process */
	CS_EXEC_SET_KILL        CsCodeDirectoryFlag = 0x00200000 /* set CS_KILL on any exec'ed process */
	CS_EXEC_SET_ENFORCEMENT CsCodeDirectoryFlag = 0x00400000 /* set CS_ENFORCEMENT on any exec'ed process */
	CS_EXEC_INHERIT_SIP     CsCodeDirectoryFlag = 0x00800000 /* set CS_INSTALLER on any exec'ed process */

	CS_KILLED          CsCodeDirectoryFlag = 0x01000000 /* was killed by kernel for invalidity */
	CS_DYLD_PLATFORM   CsCodeDirectoryFlag = 0x02000000 /* dyld used to load this is a platform binary */
	CS_PLATFORM_BINARY CsCodeDirectoryFlag = 0x04000000 /* this is a platform binary */
	CS_PLATFORM_PATH   CsCodeDirectoryFlag = 0x08000000 /* platform binary by the fact of path (osx only) */

	CS_DEBUGGED             CsCodeDirectoryFlag = 0x10000000 /* process is currently or has previously been debugged and allowed to run with invalid pages */
	CS_SIGNED               CsCodeDirectoryFlag = 0x20000000 /* process has a signature (may have gone invalid) */
	CS_DEV_CODE             CsCodeDirectoryFlag = 0x40000000 /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
	CS_DATAVAULT_CONTROLLER CsCodeDirectoryFlag = 0x80000000 /* has Data Vault controller entitlement */

	CS_ENTITLEMENT_FLAGS CsCodeDirectoryFlag = (CS_GET_TASK_ALLOW | CS_INSTALLER | CS_DATAVAULT_CONTROLLER | CS_NVRAM_UNRESTRICTED)
)

// C form of a CodeDirectory.
type CsCodeDirectory struct {
	Magic         CsMagic             // magic number (CSMAGIC_CODEDIRECTORY) */
	Length        uint32              // total length of CodeDirectory blob
	Version       CDVersion           // compatibility version
	Flags         CsCodeDirectoryFlag // setup and mode flags
	HashOffset    uint32              // offset of hash slot element at index zero
	IdentOffset   uint32              // offset of identifier string
	NSpecialSlots uint32              // number of special hash slots
	NCodeSlots    uint32              // number of ordinary (code) hash slots
	CodeLimit     uint32              // limit to main image signature range
	HashSize      uint8               // size of each hash in bytes
	HashType      CsHashType          // type of hash (cdHashType* constants)
	Platform      uint8               // platform identifier zero if not platform binary
	PageSize      uint8               // log2(page size in bytes) 0 => infinite
	Spare2        uint32              // unused (must be zero)

	EndEarliest [0]uint8

	/* Version 0x20100 */
	ScatterOffset  uint32 /* offset of optional scatter vector */
	EndWithScatter [0]uint8

	/* Version 0x20200 */
	TeamOffset  uint32 /* offset of optional team identifier */
	EndWithTeam [0]uint8

	/* Version 0x20300 */
	Spare3             uint32 /* unused (must be zero) */
	CodeLimit64        uint64 /* limit to main image signature range, 64 bits */
	EndWithCodeLimit64 [0]uint8

	/* Version 0x20400 */
	ExecSegBase    uint64      /* offset of executable segment */
	ExecSegLimit   uint64      /* limit of executable segment */
	ExecSegFlags   ExecSegFlag /* exec segment flags */
	EndWithExecSeg [0]uint8

	/* followed by dynamic content as located by offset fields above */
}

type ExecSegFlag uint64

/* executable segment flags */
const (
	CS_EXECSEG_MAIN_BINARY     ExecSegFlag = 0x1   /* executable segment denotes main binary */
	CS_EXECSEG_ALLOW_UNSIGNED  ExecSegFlag = 0x10  /* allow unsigned pages (for debugging) */
	CS_EXECSEG_DEBUGGER        ExecSegFlag = 0x20  /* main binary is debugger */
	CS_EXECSEG_JIT             ExecSegFlag = 0x40  /* JIT enabled */
	CS_EXECSEG_SKIP_LV         ExecSegFlag = 0x80  /* OBSOLETE: skip library validation */
	CS_EXECSEG_CAN_LOAD_CDHASH ExecSegFlag = 0x100 /* can bless cdhash for execution */
	CS_EXECSEG_CAN_EXEC_CDHASH ExecSegFlag = 0x200 /* can execute blessed cdhash */
)

/* Version 0x20400 */
type CsCodeDirExecSeg struct {
	ExecSegBase    uint64      /* offset of executable segment */
	ExecSegLimit   uint64      /* limit of executable segment */
	ExecSegFlags   ExecSegFlag /* exec segment flags */
	EndWithExecSeg [0]uint8
}

type CsBlob struct {
	Magic  CsMagic // magic number
	Length uint32  // total length of blob
}

type CsRequirementsBlob struct {
	Magic  CsMagic // magic number
	Length uint32  // total length of blob
	Data   uint32  // zero for dyld shared cache
}

type CsRequirements struct {
	Type   CsRequirementType // type of entry
	Offset uint32            // offset of entry
}

type CsRequirement struct {
	Detail string
	CsRequirementsBlob
	CsRequirements
}

type CsScatter struct {
	Count        uint32 // number of pages zero for sentinel (only)
	Base         uint32 // first page number
	TargetOffset uint64 // byte offset in target
	Spare        uint64 // reserved (must be zero)
}
