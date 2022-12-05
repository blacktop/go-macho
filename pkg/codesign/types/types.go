package types

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	mtypes "github.com/blacktop/go-macho/types"
)

const (
	pageSizeBits      = 12
	pageSize          = 1 << pageSizeBits
	blobSize          = 2 * 4
	superBlobSize     = 3 * 4
	codeDirectorySize = 13*4 + 4 + 4*8
)

// CodeSignature highlevel object
type CodeSignature struct {
	CodeDirectories []CodeDirectory
	Requirements    []Requirement
	CMSSignature    []byte
	Entitlements    string
	EntitlementsDER []byte
	Errors          []error
}

type magic uint32

// SuperBlob object
type SuperBlob struct {
	Magic  magic  // magic number
	Length uint32 // total length of SuperBlob
	Count  uint32 // number of index entries following
	// Index  []CsBlobIndex // (count) entries
	// followed by Blobs in no particular order as indicated by offsets in index
}

func (s *SuperBlob) put(out []byte) []byte {
	out = put32be(out, uint32(s.Magic))
	out = put32be(out, s.Length)
	out = put32be(out, s.Count)
	return out
}

// BlobIndex object
type BlobIndex struct {
	Type   SlotType // type of entry
	Offset uint32   // offset of entry
}

// Blob object
type Blob struct {
	Magic  magic  // magic number
	Length uint32 // total length of blob
}

func (b *Blob) put(out []byte) []byte {
	out = put32be(out, uint32(b.Magic))
	out = put32be(out, b.Length)
	return out
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

var magicStrings = []mtypes.IntName{
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

func (cm magic) String() string   { return mtypes.StringName(uint32(cm), magicStrings, false) }
func (cm magic) GoString() string { return mtypes.StringName(uint32(cm), magicStrings, true) }

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

var NULL_PAGE_SHA256_HASH = []byte{0xad, 0x7f, 0xac, 0xb2, 0x58, 0x6f, 0xc6, 0xe9, 0x66, 0xc0, 0x04, 0xd7, 0xd1, 0xd1, 0x6b, 0x02, 0x4f, 0x58, 0x05, 0xff, 0x7c, 0xb4, 0x7c, 0x7a, 0x85, 0xda, 0xbd, 0x8b, 0x48, 0x89, 0x2c, 0xa7}

type SlotType uint32

const (
	CSSLOT_CODEDIRECTORY                 SlotType = 0
	CSSLOT_INFOSLOT                      SlotType = 1      // Info.plist
	CSSLOT_REQUIREMENTS                  SlotType = 2      // internal requirements
	CSSLOT_RESOURCEDIR                   SlotType = 3      // resource directory
	CSSLOT_APPLICATION                   SlotType = 4      // Application specific slot/Top-level directory list
	CSSLOT_ENTITLEMENTS                  SlotType = 5      // embedded entitlement configuration
	CSSLOT_REP_SPECIFIC                  SlotType = 6      // for use by disk images
	CSSLOT_ENTITLEMENTS_DER              SlotType = 7      // DER representation of entitlements plist
	CSSLOT_ALTERNATE_CODEDIRECTORIES     SlotType = 0x1000 // Used for expressing a code directory using an alternate digest type.
	CSSLOT_ALTERNATE_CODEDIRECTORIES1    SlotType = 0x1001 // Used for expressing a code directory using an alternate digest type.
	CSSLOT_ALTERNATE_CODEDIRECTORIES2    SlotType = 0x1002 // Used for expressing a code directory using an alternate digest type.
	CSSLOT_ALTERNATE_CODEDIRECTORIES3    SlotType = 0x1003 // Used for expressing a code directory using an alternate digest type.
	CSSLOT_ALTERNATE_CODEDIRECTORIES4    SlotType = 0x1004 // Used for expressing a code directory using an alternate digest type.
	CSSLOT_ALTERNATE_CODEDIRECTORY_MAX            = 5
	CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT          = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX
	CSSLOT_CMS_SIGNATURE                 SlotType = 0x10000 // CMS signature
	CSSLOT_IDENTIFICATIONSLOT            SlotType = 0x10001 // identification blob; used for detached signature
	CSSLOT_TICKETSLOT                    SlotType = 0x10002 // Notarization ticket
)

var slotTypeStrings = []mtypes.IntName{
	{uint32(CSSLOT_CODEDIRECTORY), "CodeDirectory"},
	{uint32(CSSLOT_INFOSLOT), "Bound Info.plist"},
	{uint32(CSSLOT_REQUIREMENTS), "Requirements Blob"},
	{uint32(CSSLOT_RESOURCEDIR), "Resource Directory"},
	{uint32(CSSLOT_APPLICATION), "Application Specific"},
	{uint32(CSSLOT_ENTITLEMENTS), "Entitlements Plist"},
	{uint32(CSSLOT_REP_SPECIFIC), "DMG Specific"},
	{uint32(CSSLOT_ENTITLEMENTS_DER), "Entitlements ASN1/DER"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORIES), "Alternate CodeDirectories"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORY_MAX), "Alternate CodeDirectory Max"},
	{uint32(CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT), "Alternate CodeDirectory Limit"},
	{uint32(CSSLOT_CMS_SIGNATURE), "CMS (RFC3852) signature"},
	{uint32(CSSLOT_IDENTIFICATIONSLOT), "IdentificationSlot"},
	{uint32(CSSLOT_TICKETSLOT), "TicketSlot"},
}

func (c SlotType) String() string {
	return mtypes.StringName(uint32(c), slotTypeStrings, false)
}
func (c SlotType) GoString() string {
	return mtypes.StringName(uint32(c), slotTypeStrings, true)
}

func put32be(b []byte, x uint32) []byte { binary.BigEndian.PutUint32(b, x); return b[4:] }
func put64be(b []byte, x uint64) []byte { binary.BigEndian.PutUint64(b, x); return b[8:] }
func put8(b []byte, x uint8) []byte     { b[0] = x; return b[1:] }
func puts(b, s []byte) []byte           { n := copy(b, s); return b[n:] }

// Size computes the size of the code signature.
// id is the identifier used for signing (a field in CodeDirectory blob, which
// has no significance in ad-hoc signing).
func size(codeSize int64, id string) int64 {
	nhashes := (codeSize + pageSize - 1) / pageSize
	idOff := int64(codeDirectorySize)
	hashOff := idOff + int64(len(id)+1)
	cdirSz := hashOff + nhashes*sha256.Size
	return int64(superBlobSize+blobSize) + cdirSz
}

func Sign(out []byte, data io.Reader, id string, codeSize, textOff, textSize int64, isMain bool, flags uint32) {

	nhashes := (codeSize + pageSize - 1) / pageSize
	idOff := int64(codeDirectorySize)
	hashOff := idOff + int64(len(id)+1)
	sz := size(codeSize, id)

	// emit blob headers
	sb := SuperBlob{
		Magic:  MAGIC_EMBEDDED_SIGNATURE,
		Length: uint32(sz),
		Count:  1,
	}
	blob := Blob{
		Magic:  magic(CSSLOT_CODEDIRECTORY),
		Length: superBlobSize + blobSize,
	}
	cdir := CodeDirectoryType{
		Magic:        MAGIC_CODEDIRECTORY,
		Length:       uint32(sz) - (superBlobSize + blobSize),
		Version:      SUPPORTS_EXECSEG,
		Flags:        cdFlag(flags),
		HashOffset:   uint32(hashOff),
		IdentOffset:  uint32(idOff),
		NCodeSlots:   uint32(nhashes),
		CodeLimit:    uint32(codeSize),
		HashSize:     sha256.Size,
		HashType:     HASHTYPE_SHA256,
		PageSize:     uint8(pageSizeBits),
		ExecSegBase:  uint64(textOff),
		ExecSegLimit: uint64(textSize),
	}
	if isMain {
		cdir.ExecSegFlags = EXECSEG_MAIN_BINARY
	}

	outp := out
	outp = sb.put(outp)
	outp = blob.put(outp)
	outp = cdir.put(outp)

	// emit the identifier
	outp = puts(outp, []byte(id+"\000"))

	// emit hashes
	var buf [pageSize]byte
	h := sha256.New()
	p := 0
	for p < int(codeSize) {
		n, err := io.ReadFull(data, buf[:])
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			panic(err)
		}
		if p+n > int(codeSize) {
			n = int(codeSize) - p
		}
		p += n
		h.Reset()
		h.Write(buf[:n])
		b := h.Sum(nil)
		outp = puts(outp, b[:])
	}
}
