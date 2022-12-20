package types

import (
	mtypes "github.com/appsworld/go-macho/types"
)

// CodeDirectory object
type CodeDirectory struct {
	ID             string
	TeamID         string
	Scatter        Scatter
	CDHash         string
	SpecialSlots   []SpecialSlot
	CodeSlots      []CodeSlot
	Header         CodeDirectoryType
	RuntimeVersion string
	CodeLimit      uint64

	PreEncryptSlots [][]byte
	LinkageData     []byte
}

type SpecialSlot struct {
	Index uint32
	Hash  []byte
	Desc  string
}

type CodeSlot struct {
	Index uint32
	Page  uint32
	Hash  []byte
	Desc  string
}

type hashType uint8

const (
	PAGE_SIZE = 4096

	HASHTYPE_NOHASH           hashType = 0
	HASHTYPE_SHA1             hashType = 1
	HASHTYPE_SHA256           hashType = 2
	HASHTYPE_SHA256_TRUNCATED hashType = 3
	HASHTYPE_SHA384           hashType = 4
	HASHTYPE_SHA512           hashType = 5

	HASH_SIZE_SHA1             = 20
	HASH_SIZE_SHA256           = 32
	HASH_SIZE_SHA256_TRUNCATED = 20

	CDHASH_LEN    = 20 /* always - larger hashes are truncated */
	HASH_MAX_SIZE = 48 /* max size of the hash we'll support */
)

var csHashTypeStrings = []mtypes.IntName{
	{uint32(HASHTYPE_NOHASH), "No Hash"},
	{uint32(HASHTYPE_SHA1), "Sha1"},
	{uint32(HASHTYPE_SHA256), "Sha256"},
	{uint32(HASHTYPE_SHA256_TRUNCATED), "Sha256 (Truncated)"},
	{uint32(HASHTYPE_SHA384), "Sha384"},
	{uint32(HASHTYPE_SHA512), "Sha512"},
}

func (c hashType) String() string   { return mtypes.StringName(uint32(c), csHashTypeStrings, false) }
func (c hashType) GoString() string { return mtypes.StringName(uint32(c), csHashTypeStrings, true) }

type cdVersion uint32

const (
	EARLIEST_VERSION     cdVersion = 0x20001
	SUPPORTS_SCATTER     cdVersion = 0x20100
	SUPPORTS_TEAMID      cdVersion = 0x20200
	SUPPORTS_CODELIMIT64 cdVersion = 0x20300
	SUPPORTS_EXECSEG     cdVersion = 0x20400
	SUPPORTS_RUNTIME     cdVersion = 0x20500
	SUPPORTS_LINKAGE     cdVersion = 0x20600
	COMPATIBILITY_LIMIT  cdVersion = 0x2F000 // "version 3 with wiggle room"
)

var csVersionypeStrings = []mtypes.IntName{
	{uint32(SUPPORTS_SCATTER), "Scatter"},
	{uint32(SUPPORTS_TEAMID), "TeamID"},
	{uint32(SUPPORTS_CODELIMIT64), "Codelimit64"},
	{uint32(SUPPORTS_EXECSEG), "ExecSeg"},
	{uint32(SUPPORTS_RUNTIME), "Runtime"},
	{uint32(SUPPORTS_LINKAGE), "Linkage"},
}

func (v cdVersion) String() string {
	return mtypes.StringName(uint32(v), csVersionypeStrings, false)
}
func (v cdVersion) GoString() string {
	return mtypes.StringName(uint32(v), csVersionypeStrings, true)
}

type cdFlag uint32

const (
	/* code signing attributes of a process */
	NONE           cdFlag = 0x00000000 /* no flags */
	VALID          cdFlag = 0x00000001 /* dynamically valid */
	ADHOC          cdFlag = 0x00000002 /* ad hoc signed */
	GET_TASK_ALLOW cdFlag = 0x00000004 /* has get-task-allow entitlement */
	INSTALLER      cdFlag = 0x00000008 /* has installer entitlement */

	FORCED_LV       cdFlag = 0x00000010 /* Library Validation required by Hardened System Policy */
	INVALID_ALLOWED cdFlag = 0x00000020 /* (macOS Only) Page invalidation allowed by task port policy */

	HARD             cdFlag = 0x00000100 /* don't load invalid pages */
	KILL             cdFlag = 0x00000200 /* kill process if it becomes invalid */
	CHECK_EXPIRATION cdFlag = 0x00000400 /* force expiration checking */
	RESTRICT         cdFlag = 0x00000800 /* tell dyld to treat restricted */

	ENFORCEMENT            cdFlag = 0x00001000 /* require enforcement */
	REQUIRE_LV             cdFlag = 0x00002000 /* require library validation */
	ENTITLEMENTS_VALIDATED cdFlag = 0x00004000 /* code signature permits restricted entitlements */
	NVRAM_UNRESTRICTED     cdFlag = 0x00008000 /* has com.apple.rootless.restricted-nvram-variables.heritable entitlement */

	RUNTIME cdFlag = 0x00010000 /* Apply hardened runtime policies */

	LINKER_SIGNED cdFlag = 0x20000 // type property

	ALLOWED_MACHO cdFlag = (ADHOC | HARD | KILL | CHECK_EXPIRATION | RESTRICT | ENFORCEMENT | REQUIRE_LV | RUNTIME)

	EXEC_SET_HARD        cdFlag = 0x00100000 /* set HARD on any exec'ed process */
	EXEC_SET_KILL        cdFlag = 0x00200000 /* set KILL on any exec'ed process */
	EXEC_SET_ENFORCEMENT cdFlag = 0x00400000 /* set ENFORCEMENT on any exec'ed process */
	EXEC_INHERIT_SIP     cdFlag = 0x00800000 /* set INSTALLER on any exec'ed process */

	KILLED          cdFlag = 0x01000000 /* was killed by kernel for invalidity */
	DYLD_PLATFORM   cdFlag = 0x02000000 /* dyld used to load this is a platform binary */
	PLATFORM_BINARY cdFlag = 0x04000000 /* this is a platform binary */
	PLATFORM_PATH   cdFlag = 0x08000000 /* platform binary by the fact of path (osx only) */

	DEBUGGED             cdFlag = 0x10000000 /* process is currently or has previously been debugged and allowed to run with invalid pages */
	SIGNED               cdFlag = 0x20000000 /* process has a signature (may have gone invalid) */
	DEV_CODE             cdFlag = 0x40000000 /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
	DATAVAULT_CONTROLLER cdFlag = 0x80000000 /* has Data Vault controller entitlement */

	ENTITLEMENT_FLAGS cdFlag = (GET_TASK_ALLOW | INSTALLER | DATAVAULT_CONTROLLER | NVRAM_UNRESTRICTED)
)

var cdFlagStrings = []mtypes.IntName{ // TODO: what about flag combinations?
	{uint32(NONE), "None"},
	{uint32(VALID), "Valid"},
	{uint32(ADHOC), "Adhoc"},
	{uint32(GET_TASK_ALLOW), "GetTaskAllow"},
	{uint32(INSTALLER), "Installer"},
	{uint32(FORCED_LV), "ForcedLv"},
	{uint32(INVALID_ALLOWED), "InvalidAllowed"},
	{uint32(HARD), "Hard"},
	{uint32(KILL), "Kill"},
	{uint32(CHECK_EXPIRATION), "CheckExpiration"},
	{uint32(RESTRICT), "Restrict"},
	{uint32(ENFORCEMENT), "Enforcement"},
	{uint32(REQUIRE_LV), "RequireLv"},
	{uint32(ENTITLEMENTS_VALIDATED), "EntitlementsValidated"},
	{uint32(NVRAM_UNRESTRICTED), "NvramUnrestricted"},
	{uint32(RUNTIME), "Runtime"},
	{uint32(LINKER_SIGNED), "LinkerSigned"},
	{uint32(ALLOWED_MACHO), "AllowedMacho"},
	{uint32(EXEC_SET_HARD), "ExecSetHard"},
	{uint32(EXEC_SET_KILL), "ExecSetKill"},
	{uint32(EXEC_SET_ENFORCEMENT), "ExecSetEnforcement"},
	{uint32(EXEC_INHERIT_SIP), "ExecInheritSip"},
	{uint32(KILLED), "Killed"},
	{uint32(DYLD_PLATFORM), "DyldPlatform"},
	{uint32(PLATFORM_BINARY), "PlatformBinary"},
	{uint32(PLATFORM_PATH), "PlatformPath"},
	{uint32(DEBUGGED), "Debugged"},
	{uint32(SIGNED), "Signed"},
	{uint32(DEV_CODE), "DevCode"},
	{uint32(DATAVAULT_CONTROLLER), "DatavaultController"},
	{uint32(ENTITLEMENT_FLAGS), "EntitlementFlags"},
}

func (f cdFlag) String() string {
	return mtypes.StringName(uint32(f), cdFlagStrings, false)
}
func (f cdFlag) GoString() string {
	return mtypes.StringName(uint32(f), cdFlagStrings, true)
}

// CodeDirectoryType header
type CodeDirectoryType struct {
	Magic         magic     // magic number (CSMAGIC_CODEDIRECTORY) */
	Length        uint32    // total length of CodeDirectory blob
	Version       cdVersion // compatibility version
	Flags         cdFlag    // setup and mode flags
	HashOffset    uint32    // offset of hash slot element at index zero
	IdentOffset   uint32    // offset of identifier string
	NSpecialSlots uint32    // number of special hash slots
	NCodeSlots    uint32    // number of ordinary (code) hash slots
	CodeLimit     uint32    // limit to main image signature range
	HashSize      uint8     // size of each hash in bytes
	HashType      hashType  // type of hash (cdHashType* constants)
	Platform      uint8     // platform identifier zero if not platform binary
	PageSize      uint8     // log2(page size in bytes) 0 => infinite
	Spare2        uint32    // unused (must be zero)

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
	ExecSegFlags   execSegFlag /* exec segment flags */
	EndWithExecSeg [0]uint8

	/* Version 0x20500 */
	Runtime                 mtypes.Version // Runtime version
	PreEncryptOffset        uint32         // offset of pre-encrypt hash slots
	EndWithPreEncryptOffset [0]uint8

	/* Version 0x20600 */
	LinkageHashType  uint8
	LinkageTruncated uint8
	Spare4           uint16
	LinkageOffset    uint32
	LinkageSize      uint32
	EndWithLinkage   [0]uint8

	/* followed by dynamic content as located by offset fields above */
}

func (c *CodeDirectoryType) put(out []byte) []byte {
	out = put32be(out, uint32(c.Magic))
	out = put32be(out, c.Length)
	out = put32be(out, uint32(c.Version))
	out = put32be(out, uint32(c.Flags))
	out = put32be(out, c.HashOffset)
	out = put32be(out, c.IdentOffset)
	out = put32be(out, c.NSpecialSlots)
	out = put32be(out, c.NCodeSlots)
	out = put32be(out, c.CodeLimit)
	out = put8(out, c.HashSize)
	out = put8(out, uint8(c.HashType))
	out = put8(out, c.Platform)
	out = put8(out, c.PageSize)
	out = put32be(out, c.Spare2)
	out = put32be(out, c.ScatterOffset)
	out = put32be(out, c.TeamOffset)
	out = put32be(out, c.Spare3)
	out = put64be(out, c.CodeLimit64)
	out = put64be(out, c.ExecSegBase)
	out = put64be(out, c.ExecSegLimit)
	out = put64be(out, uint64(c.ExecSegFlags))
	return out
}

// Scatter object
type Scatter struct {
	Count        uint32 // number of pages zero for sentinel (only)
	Base         uint32 // first page number
	TargetOffset uint64 // byte offset in target
	Spare        uint64 // reserved (must be zero)
}

type execSegFlag uint64

/* executable segment flags */
const (
	EXECSEG_MAIN_BINARY     execSegFlag = 0x1   /* executable segment denotes main binary */
	EXECSEG_ALLOW_UNSIGNED  execSegFlag = 0x10  /* allow unsigned pages (for debugging) */
	EXECSEG_DEBUGGER        execSegFlag = 0x20  /* main binary is debugger */
	EXECSEG_JIT             execSegFlag = 0x40  /* JIT enabled */
	EXECSEG_SKIP_LV         execSegFlag = 0x80  /* OBSOLETE: skip library validation */
	EXECSEG_CAN_LOAD_CDHASH execSegFlag = 0x100 /* can bless cdhash for execution */
	EXECSEG_CAN_EXEC_CDHASH execSegFlag = 0x200 /* can execute blessed cdhash */
)

var execSegFlagStrings = []mtypes.Int64Name{
	{I: uint64(EXECSEG_MAIN_BINARY), S: "Main Binary"},
	{I: uint64(EXECSEG_ALLOW_UNSIGNED), S: "Allow Unsigned"},
	{I: uint64(EXECSEG_DEBUGGER), S: "Debugger"},
	{I: uint64(EXECSEG_JIT), S: "JIT"},
	{I: uint64(EXECSEG_SKIP_LV), S: "Skip LV"},
	{I: uint64(EXECSEG_CAN_LOAD_CDHASH), S: "Can Load CDHash"},
	{I: uint64(EXECSEG_CAN_EXEC_CDHASH), S: "Can Exec CDHash"},
}

func (f execSegFlag) String() string {
	return mtypes.StringName64(uint64(f), execSegFlagStrings, false)
}
func (f execSegFlag) GoString() string {
	return mtypes.StringName64(uint64(f), execSegFlagStrings, true)
}
