package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

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
)

var NULL_PAGE_SHA256_HASH = []byte{
	0xad, 0x7f, 0xac, 0xb2, 0x58, 0x6f, 0xc6, 0xe9,
	0x66, 0xc0, 0x04, 0xd7, 0xd1, 0xd1, 0x6b, 0x02,
	0x4f, 0x58, 0x05, 0xff, 0x7c, 0xb4, 0x7c, 0x7a,
	0x85, 0xda, 0xbd, 0x8b, 0x48, 0x89, 0x2c, 0xa7,
}

type Magic uint32

const (
	// Magic numbers used by Code Signing
	MAGIC_REQUIREMENT               Magic = 0xfade0c00 // single Requirement blob
	MAGIC_REQUIREMENTS              Magic = 0xfade0c01 // Requirements vector (internal requirements)
	MAGIC_CODEDIRECTORY             Magic = 0xfade0c02 // CodeDirectory blob
	MAGIC_EMBEDDED_SIGNATURE        Magic = 0xfade0cc0 // embedded form of signature data
	MAGIC_EMBEDDED_SIGNATURE_OLD    Magic = 0xfade0b02 /* XXX */
	MAGIC_LIBRARY_DEPENDENCY_BLOB   Magic = 0xfade0c05
	MAGIC_EMBEDDED_ENTITLEMENTS     Magic = 0xfade7171 /* embedded entitlements */
	MAGIC_EMBEDDED_ENTITLEMENTS_DER Magic = 0xfade7172 /* embedded entitlements */
	MAGIC_DETACHED_SIGNATURE        Magic = 0xfade0cc1 // multi-arch collection of embedded signatures
	MAGIC_BLOBWRAPPER               Magic = 0xfade0b01 // used for the cms blob
)

func (cm Magic) String() string {
	switch cm {
	case MAGIC_REQUIREMENT:
		return "Requirement"
	case MAGIC_REQUIREMENTS:
		return "Requirements"
	case MAGIC_CODEDIRECTORY:
		return "Codedirectory"
	case MAGIC_EMBEDDED_SIGNATURE:
		return "Embedded Signature"
	case MAGIC_EMBEDDED_SIGNATURE_OLD:
		return "Embedded Signature (Old)"
	case MAGIC_LIBRARY_DEPENDENCY_BLOB:
		return "Library Dependency Blob"
	case MAGIC_EMBEDDED_ENTITLEMENTS:
		return "Embedded Entitlements"
	case MAGIC_EMBEDDED_ENTITLEMENTS_DER:
		return "Embedded Entitlements (DER)"
	case MAGIC_DETACHED_SIGNATURE:
		return "Detached Signature"
	case MAGIC_BLOBWRAPPER:
		return "Blob Wrapper"
	default:
		return fmt.Sprintf("Magic(%#x)", uint32(cm))
	}
}

type SbHeader struct {
	Magic  Magic  // magic number
	Length uint32 // total length of SuperBlob
	Count  uint32 // number of index entries following
}

// SuperBlob object
type SuperBlob struct {
	SbHeader
	Index []BlobIndex // (count) entries
	Blobs []Blob      // followed by Blobs in no particular order as indicated by offsets in index
}

func NewSuperBlob(magic Magic) SuperBlob {
	return SuperBlob{
		SbHeader: SbHeader{
			Magic: magic,
		},
	}
}

func (s *SuperBlob) AddBlob(typ SlotType, blob Blob) {
	idx := BlobIndex{
		Type: typ,
	}
	s.Index = append(s.Index, idx)
	s.Blobs = append(s.Blobs, blob)
	s.Count++
	s.Length += blob.Length + uint32(binary.Size(idx))
}

func (s *SuperBlob) Write(buf *bytes.Buffer, o binary.ByteOrder) error {
	off := uint32(binary.Size(s.SbHeader) + binary.Size(s.Index))
	for i := range s.Index {
		s.Index[i].Offset = off
		off += s.Blobs[i].Length
	}
	if err := binary.Write(buf, o, s.SbHeader); err != nil {
		return fmt.Errorf("failed to write SuperBlob header to buffer: %v", err)
	}
	if err := binary.Write(buf, o, s.Index); err != nil {
		return fmt.Errorf("failed to write SuperBlob indices to buffer: %v", err)
	}
	for _, blob := range s.Blobs {
		if err := binary.Write(buf, o, blob.BlobHeader); err != nil {
			return fmt.Errorf("failed to write blob header to superblob buffer: %v", err)
		}
		if err := binary.Write(buf, o, blob.Data); err != nil {
			return fmt.Errorf("failed to write blob data to superblob buffer: %v", err)
		}
	}
	// TODO: padding ?
	return nil
}

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

func (c SlotType) String() string {
	switch c {
	case CSSLOT_CODEDIRECTORY:
		return "CodeDirectory"
	case CSSLOT_INFOSLOT:
		return "Bound Info.plist"
	case CSSLOT_REQUIREMENTS:
		return "Requirements Blob"
	case CSSLOT_RESOURCEDIR:
		return "Resource Directory"
	case CSSLOT_APPLICATION:
		return "Application Specific"
	case CSSLOT_ENTITLEMENTS:
		return "Entitlements Plist"
	case CSSLOT_REP_SPECIFIC:
		return "DMG Specific"
	case CSSLOT_ENTITLEMENTS_DER:
		return "Entitlements ASN1/DER"
	case CSSLOT_ALTERNATE_CODEDIRECTORIES:
		return "Alternate CodeDirectories 0"
	case CSSLOT_ALTERNATE_CODEDIRECTORIES1:
		return "Alternate CodeDirectories 1"
	case CSSLOT_ALTERNATE_CODEDIRECTORIES2:
		return "Alternate CodeDirectories 2"
	case CSSLOT_ALTERNATE_CODEDIRECTORIES3:
		return "Alternate CodeDirectories 3"
	case CSSLOT_ALTERNATE_CODEDIRECTORIES4:
		return "Alternate CodeDirectories 4"
	case CSSLOT_CMS_SIGNATURE:
		return "CMS (RFC3852) signature"
	case CSSLOT_IDENTIFICATIONSLOT:
		return "IdentificationSlot"
	case CSSLOT_TICKETSLOT:
		return "TicketSlot"
	default:
		return fmt.Sprintf("Unknown SlotType: %d", c)
	}
}

// BlobIndex object
type BlobIndex struct {
	Type   SlotType // type of entry
	Offset uint32   // offset of entry
}

type BlobHeader struct {
	Magic  Magic  // magic number
	Length uint32 // total length of blob
}

// Blob object
type Blob struct {
	BlobHeader
	Data any // (length - sizeof(blob_header)) bytes
}

func NewBlob(magic Magic, data any) Blob {
	return Blob{
		BlobHeader: BlobHeader{
			Magic:  magic,
			Length: uint32(binary.Size(BlobHeader{}) + binary.Size(data)),
		},
		Data: data,
	}
}

func (b Blob) Sha256Hash() ([]byte, error) {
	h := sha256.New()
	if err := binary.Write(h, binary.BigEndian, b.BlobHeader); err != nil {
		return nil, fmt.Errorf("failed to hash blob header: %v", err)
	}
	if err := binary.Write(h, binary.BigEndian, b.Data); err != nil {
		return nil, fmt.Errorf("failed to hash blob header: %v", err)
	}
	return h.Sum(nil), nil

}
