package codesign

import "github.com/blacktop/go-macho/types"

type magic uint32

// SuperBlob object
type SuperBlob struct {
	Magic  magic  // magic number
	Length uint32 // total length of SuperBlob
	Count  uint32 // number of index entries following
	// Index  []CsBlobIndex // (count) entries
	// followed by Blobs in no particular order as indicated by offsets in index
}

// BlobIndex object
type BlobIndex struct {
	Type   slotType // type of entry
	Offset uint32   // offset of entry
}

// Blob object
type Blob struct {
	Magic  magic  // magic number
	Length uint32 // total length of blob
}

const (
	// Magic numbers used by Code Signing
	MAGIC_REQUIREMENT               magic = 0xfade0c00 // single Requirement blob
	MAGIC_REQUIREMENTS              magic = 0xfade0c01 // Requirements vector (internal requirements)
	MAGIC_CODEDIRECTORY             magic = 0xfade0c02 // CodeDirectory blob
	MAGIC_EMBEDDED_SIGNATURE        magic = 0xfade0cc0 // embedded form of signature data
	MAGIC_EMBEDDED_SIGNATURE_OLD    magic = 0xfade0b02 /* XXX */
	MAGIC_LIBRARY_DEPENDENCY_BLOB   magic = 0xfade0c05
	MAGIC_EMBEDDED_ENTITLEMENTS     magic = 0xfade7171 /* embedded entitlements */
	MAGIC_EMBEDDED_ENTITLEMENTS_DER magic = 0xfade7172 /* embedded entitlements */
	MAGIC_DETACHED_SIGNATURE        magic = 0xfade0cc1 // multi-arch collection of embedded signatures
	MAGIC_BLOBWRAPPER               magic = 0xfade0b01 // used for the cms blob
)

var magicStrings = []types.IntName{
	{uint32(MAGIC_REQUIREMENT), "Requirement"},
	{uint32(MAGIC_REQUIREMENTS), "Requirements"},
	{uint32(MAGIC_CODEDIRECTORY), "Codedirectory"},
	{uint32(MAGIC_EMBEDDED_SIGNATURE), "Embedded Signature"},
	{uint32(MAGIC_EMBEDDED_SIGNATURE_OLD), "Embedded Signature (Old)"},
	{uint32(MAGIC_LIBRARY_DEPENDENCY_BLOB), "Library Dependency Blob"},
	{uint32(MAGIC_EMBEDDED_ENTITLEMENTS), "Embedded Entitlements"},
	{uint32(MAGIC_EMBEDDED_ENTITLEMENTS_DER), "Embedded Entitlements (DER)"},
	{uint32(MAGIC_DETACHED_SIGNATURE), "Detached Signature"},
	{uint32(MAGIC_BLOBWRAPPER), "Blob Wrapper"},
}

func (cm magic) String() string   { return types.StringName(uint32(cm), magicStrings, false) }
func (cm magic) GoString() string { return types.StringName(uint32(cm), magicStrings, true) }

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

type slotType uint32

const (
	CSSLOT_CODEDIRECTORY                 slotType = 0
	CSSLOT_INFOSLOT                      slotType = 1
	CSSLOT_REQUIREMENTS                  slotType = 2
	CSSLOT_RESOURCEDIR                   slotType = 3
	CSSLOT_APPLICATION                   slotType = 4
	CSSLOT_ENTITLEMENTS                  slotType = 5
	CSSLOT_ALTERNATE_CODEDIRECTORIES     slotType = 0x1000
	CSSLOT_ALTERNATE_CODEDIRECTORY_MAX            = 5
	CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT          = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX
	CSSLOT_CMS_SIGNATURE                 slotType = 0x10000
	CSSLOT_IDENTIFICATIONSLOT            slotType = 0x10001
	CSSLOT_TICKETSLOT                    slotType = 0x10002
)

var slotTypeStrings = []types.IntName{
	{uint32(CSSLOT_CODEDIRECTORY), "CodeDirectory"},
	{uint32(CSSLOT_INFOSLOT), "InfoSlot"},
	{uint32(CSSLOT_REQUIREMENTS), "Requirements"},
	{uint32(CSSLOT_RESOURCEDIR), "ResourceDir"},
	{uint32(CSSLOT_APPLICATION), "Application"},
	{uint32(CSSLOT_ENTITLEMENTS), "Entitlements"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORIES), "Alternate CodeDirectories"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORY_MAX), "Alternate CodeDirectory Max"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT), "Alternate CodeDirectory Limit"},
	{uint32(CSSLOT_CMS_SIGNATURE), "CMS (RFC3852) signature"},
	{uint32(CSSLOT_IDENTIFICATIONSLOT), "IdentificationSlot"},
	{uint32(CSSLOT_TICKETSLOT), "TicketSlot"},
}

func (c slotType) String() string {
	return types.StringName(uint32(c), slotTypeStrings, false)
}
func (c slotType) GoString() string {
	return types.StringName(uint32(c), slotTypeStrings, true)
}
