package codesign

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/appsworld/go-macho/pkg/codesign/types"
)

// ParseCodeSignature parses the LC_CODE_SIGNATURE data
func ParseCodeSignature(cmddat []byte) (*types.CodeSignature, error) {
	r := bytes.NewReader(cmddat)
	cs := &types.CodeSignature{}

	csBlob := types.SuperBlob{}
	if err := binary.Read(r, binary.BigEndian, &csBlob); err != nil {
		return nil, err
	}

	csIndex := make([]types.BlobIndex, csBlob.Count)
	if err := binary.Read(r, binary.BigEndian, &csIndex); err != nil {
		return nil, err
	}

	for _, index := range csIndex {

		r.Seek(int64(index.Offset), io.SeekStart)

		switch index.Type {
		case types.CSSLOT_CODEDIRECTORY:
			fallthrough
		case types.CSSLOT_ALTERNATE_CODEDIRECTORIES:
			cd, err := parseCodeDirectory(r, index.Offset)
			if err != nil {
				return nil, err
			}
			cs.CodeDirectories = append(cs.CodeDirectories, *cd)
		case types.CSSLOT_REQUIREMENTS:
			req := types.Requirement{}
			if err := binary.Read(r, binary.BigEndian, &req.RequirementsBlob); err != nil {
				return nil, err
			}
			datLen := int(req.RequirementsBlob.Length) - binary.Size(types.RequirementsBlob{})
			if datLen > 0 {
				reqData := make([]byte, datLen)
				if err := binary.Read(r, binary.BigEndian, &reqData); err != nil {
					return nil, err
				}
				rqr := bytes.NewReader(reqData)
				if err := binary.Read(rqr, binary.BigEndian, &req.Requirements); err != nil {
					return nil, err
				}
				detail, err := types.ParseRequirements(rqr, req.Requirements)
				if err != nil {
					return nil, err
				}
				req.Detail = detail
			} else {
				req.Detail = "empty requirement set"
			}
			cs.Requirements = append(cs.Requirements, req)
		case types.CSSLOT_ENTITLEMENTS:
			entBlob := types.Blob{}
			if err := binary.Read(r, binary.BigEndian, &entBlob); err != nil {
				return nil, err
			}
			plistData := make([]byte, int(entBlob.Length)-binary.Size(entBlob))
			if err := binary.Read(r, binary.BigEndian, &plistData); err != nil {
				return nil, err
			}
			cs.Entitlements = string(plistData)
		case types.CSSLOT_CMS_SIGNATURE:
			cmsBlob := types.Blob{}
			if err := binary.Read(r, binary.BigEndian, &cmsBlob); err != nil {
				return nil, err
			}
			cmsData := make([]byte, int(cmsBlob.Length)-binary.Size(cmsBlob))
			if err := binary.Read(r, binary.BigEndian, &cmsData); err != nil {
				return nil, err
			}
			// NOTE: openssl pkcs7 -inform DER -in <cmsData> -print_certs -text -noout
			cs.CMSSignature = cmsData
		case types.CSSLOT_ENTITLEMENTS_DER:
			entDerBlob := types.Blob{}
			if err := binary.Read(r, binary.BigEndian, &entDerBlob); err != nil {
				return nil, err
			}
			entDerData := make([]byte, int(entDerBlob.Length)-binary.Size(entDerBlob))
			if err := binary.Read(r, binary.BigEndian, &entDerData); err != nil {
				return nil, err
			}
			cs.EntitlementsDER = entDerData
		case types.CSSLOT_REP_SPECIFIC:
			fallthrough // TODO 🤷‍♂️
		case types.CSSLOT_INFOSLOT:
			fallthrough // TODO 🤷‍♂️
		case types.CSSLOT_RESOURCEDIR:
			fallthrough // TODO 🤷‍♂️
		case types.CSSLOT_APPLICATION:
			fallthrough // TODO 🤷‍♂️
		case types.CSSLOT_IDENTIFICATIONSLOT:
			fallthrough // TODO 🤷‍♂️
		case types.CSSLOT_TICKETSLOT:
			fallthrough // TODO 🤷‍♂️
		default:
			cs.Errors = append(cs.Errors, fmt.Errorf("unknown slot type: %s, please notify author", index.Type))
		}
	}
	return cs, nil
}

func parseCodeDirectory(r *bytes.Reader, offset uint32) (*types.CodeDirectory, error) {
	var cd types.CodeDirectory
	if err := binary.Read(r, binary.BigEndian, &cd.Header); err != nil {
		return nil, err
	}
	// Calculate the cdhashs
	r.Seek(int64(offset), io.SeekStart)
	cdData := make([]byte, cd.Header.Length)
	if err := binary.Read(r, binary.LittleEndian, &cdData); err != nil {
		return nil, err
	}

	switch cd.Header.HashType {
	case types.HASHTYPE_SHA1:
		h := sha1.New()
		h.Write(cdData)
		cd.CDHash = fmt.Sprintf("%x", h.Sum(nil))
	case types.HASHTYPE_SHA256:
		h := sha256.New()
		h.Write(cdData)
		cd.CDHash = fmt.Sprintf("%x", h.Sum(nil))
	default:
		cd.CDHash = fmt.Sprintf("unsupported code directory hash type %s, please notify author", cd.Header.HashType)
	}

	// Parse version
	if cd.Header.Version < types.EARLIEST_VERSION {
		fmt.Printf("unsupported type or version of signature: %#x (too old)\n", cd.Header.Version)
	} else if cd.Header.Version > types.COMPATIBILITY_LIMIT {
		fmt.Printf("unsupported type or version of signature: %#x (too new)\n", cd.Header.Version)
	}

	// SUPPORTS_SCATTER
	if cd.Header.Version >= types.SUPPORTS_SCATTER {
		if cd.Header.ScatterOffset > 0 {
			r.Seek(int64(offset+cd.Header.ScatterOffset), io.SeekStart)
			scatter := types.Scatter{}
			if err := binary.Read(r, binary.BigEndian, &scatter); err != nil {
				return nil, fmt.Errorf("failed to read SUPPORTS_SCATTER @ %#x: %v", offset+cd.Header.ScatterOffset, err)
			}
			cd.Scatter = scatter
		}
	}
	// SUPPORTS_TEAMID
	if cd.Header.Version >= types.SUPPORTS_TEAMID {
		if cd.Header.TeamOffset > 0 {
			r.Seek(int64(offset+cd.Header.TeamOffset), io.SeekStart)
			teamID, err := bufio.NewReader(r).ReadString('\x00')
			if err != nil {
				return nil, fmt.Errorf("failed to read SUPPORTS_TEAMID @ %#x: %v", offset+cd.Header.TeamOffset, err)
			}
			cd.TeamID = strings.Trim(teamID, "\x00")
		}
	}
	// SUPPORTS_CODELIMIT64
	cd.CodeLimit = uint64(cd.Header.CodeLimit)
	if cd.Header.Version >= types.SUPPORTS_CODELIMIT64 {
		if cd.Header.CodeLimit64 > 0 {
			cd.CodeLimit = cd.Header.CodeLimit64
		}
	}
	// SUPPORTS_EXECSEG
	if cd.Header.Version >= types.SUPPORTS_EXECSEG {
		if cd.Header.ExecSegBase > 0 {
			// TODO: I don't think we do anything with this ?
		}
	}
	// SUPPORTS_RUNTIME
	if cd.Header.Version >= types.SUPPORTS_RUNTIME {
		cd.RuntimeVersion = cd.Header.Runtime.String()
		if cd.Header.PreEncryptOffset > 0 {
			r.Seek(int64(offset+cd.Header.PreEncryptOffset), io.SeekStart)
			for i := uint8(0); i < uint8(cd.Header.NCodeSlots); i++ {
				slot := make([]byte, cd.Header.HashSize)
				if err := binary.Read(r, binary.BigEndian, &slot); err != nil {
					return nil, fmt.Errorf("failed to read SUPPORTS_RUNTIME PreEncrypt hash slot #%d @ %#x: %v",
						i, offset+cd.Header.PreEncryptOffset+uint32(i*cd.Header.HashSize), err)
				}
				cd.PreEncryptSlots = append(cd.PreEncryptSlots, slot)
			}
		}
	}
	// SUPPORTS_LINKAGE
	if cd.Header.Version >= types.SUPPORTS_LINKAGE {
		if cd.Header.LinkageOffset > 0 {
			r.Seek(int64(offset+cd.Header.LinkageOffset), io.SeekStart)
			cd.LinkageData = make([]byte, cd.Header.LinkageSize)
			if err := binary.Read(r, binary.BigEndian, &cd.LinkageData); err != nil {
				return nil, fmt.Errorf("failed to read SUPPORTS_LINKAGE @ %#x: %v", offset+cd.Header.LinkageOffset, err)
			}
			// TODO: what IS linkage
		}
	}

	// Parse Indentity
	r.Seek(int64(offset+cd.Header.IdentOffset), io.SeekStart)
	id, err := bufio.NewReader(r).ReadString('\x00')
	if err != nil {
		return nil, fmt.Errorf("failed to read CodeDirectory ID at: %d: %v", offset+cd.Header.IdentOffset, err)
	}
	cd.ID = strings.Trim(id, "\x00")
	// Parse Special Slots
	r.Seek(int64(offset+cd.Header.HashOffset-(cd.Header.NSpecialSlots*uint32(cd.Header.HashSize))), io.SeekStart)
	for slot := cd.Header.NSpecialSlots; slot > 0; slot-- {
		hash := make([]byte, cd.Header.HashSize)
		if err := binary.Read(r, binary.BigEndian, &hash); err != nil {
			return nil, err
		}
		sslot := types.SpecialSlot{
			Index: slot,
			Hash:  hash,
		}
		if !bytes.Equal(hash, make([]byte, cd.Header.HashSize)) {
			sslot.Desc = fmt.Sprintf("Special Slot   %d %-22v %x", slot, types.SlotType(slot).String()+":", hash)
		} else {
			sslot.Desc = fmt.Sprintf("Special Slot   %d %-22v Not Bound", slot, types.SlotType(slot).String()+":")
		}
		cd.SpecialSlots = append(cd.SpecialSlots, sslot)
	}
	// Parse Slots
	pageSize := uint32(math.Pow(2, float64(cd.Header.PageSize)))
	for slot := uint32(0); slot < cd.Header.NCodeSlots; slot++ {
		hash := make([]byte, cd.Header.HashSize)
		if err := binary.Read(r, binary.BigEndian, &hash); err != nil {
			return nil, err
		}
		cslot := types.CodeSlot{
			Index: slot,
			Page:  slot * pageSize,
			Hash:  hash,
		}
		if bytes.Equal(hash, types.NULL_PAGE_SHA256_HASH) && cd.Header.HashType == types.HASHTYPE_SHA256 {
			cslot.Desc = fmt.Sprintf("Slot   %d (File page @0x%04X):\tNULL PAGE HASH", slot, cslot.Page)
		} else {
			cslot.Desc = fmt.Sprintf("Slot   %d (File page @0x%04X):\t%x", slot, cslot.Page, hash)
		}
		cd.CodeSlots = append(cd.CodeSlots, cslot)
	}

	return &cd, nil
}

// AdHocSign generates an ad-hoc code signature and writes it to out.
// out must have length at least Size(codeSize, id).
// data is the file content without the signature, of size codeSize.
// textOff and textSize is the file offset and size of the text segment.
// isMain is true if this is a main executable.
// id is the identifier used for signing (a field in CodeDirectory blob, which
// has no significance in ad-hoc signing).
// Similar to: `codesign --force --deep -s - MyApp.app`
func AdHocSign(out []byte, data io.Reader, id string, codeSize, textOff, textSize int64, isMain bool) {
	types.Sign(out, data, id, codeSize, textOff, textSize, isMain, uint32(types.ADHOC))
}
