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

	"github.com/blacktop/go-macho/pkg/codesign/types"
)

// ParseCodeSignature parses the LC_CODE_SIGNATURE data
func ParseCodeSignature(cmddat []byte) (*types.CodeSignature, error) {
	var err error
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
			cs.CodeDirectory, err = parseCodeDirectory(r, index.Offset)
			if err != nil {
				return nil, err
			}
		case types.CSSLOT_ALTERNATE_CODEDIRECTORIES:
			cs.AltCodeDirectory, err = parseCodeDirectory(r, index.Offset)
			if err != nil {
				return nil, err
			}
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
			cs.Requirements = &req
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
			fmt.Printf("Found unsupported codesign slot %s, please notify author\n", index.Type)
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
		fmt.Printf("Found unsupported code directory hash type %s, please notify author\n", cd.Header.HashType)
	}

	// Parse version
	switch cd.Header.Version {
	case types.SUPPORTS_SCATTER:
		if cd.Header.ScatterOffset > 0 {
			r.Seek(int64(offset+cd.Header.ScatterOffset), io.SeekStart)
			scatter := types.Scatter{}
			if err := binary.Read(r, binary.BigEndian, &scatter); err != nil {
				return nil, err
			}
			fmt.Printf("%#v\n", scatter)
		}
	case types.SUPPORTS_TEAMID:
		r.Seek(int64(offset+cd.Header.TeamOffset), io.SeekStart)
		teamID, err := bufio.NewReader(r).ReadString('\x00')
		if err != nil {
			return nil, fmt.Errorf("failed to read SUPPORTS_TEAMID at: %d: %v", offset+cd.Header.TeamOffset, err)
		}
		cd.TeamID = strings.Trim(teamID, "\x00")
	case types.SUPPORTS_CODELIMIT64:
		// TODO 🤷‍♂️
	case types.SUPPORTS_EXECSEG:
		// TODO 🤷‍♂️
	default:
		fmt.Printf("Unknown code directory version 0x%x, please notify author\n", cd.Header.Version)
	}
	// Parse Indentity
	r.Seek(int64(offset+cd.Header.IdentOffset), io.SeekStart)
	id, err := bufio.NewReader(r).ReadString('\x00')
	if err != nil {
		return nil, fmt.Errorf("failed to read CodeDirectory ID at: %d: %v", offset+cd.Header.IdentOffset, err)
	}
	cd.ID = id
	// Parse Special Slots
	r.Seek(int64(offset+cd.Header.HashOffset-(cd.Header.NSpecialSlots*uint32(cd.Header.HashSize))), io.SeekStart)
	hash := make([]byte, cd.Header.HashSize)
	for slot := cd.Header.NSpecialSlots; slot > 0; slot-- {
		if err := binary.Read(r, binary.BigEndian, &hash); err != nil {
			return nil, err
		}
		sslot := types.SpecialSlot{
			Index: slot,
			Hash:  hash,
		}
		if !bytes.Equal(hash, make([]byte, cd.Header.HashSize)) {
			sslot.Desc = fmt.Sprintf("Special Slot   %d %s:\t%x", slot, types.SlotType(slot), hash)
		} else {
			sslot.Desc = fmt.Sprintf("Special Slot   %d %s:\tNot Bound", slot, types.SlotType(slot))
		}
		cd.SpecialSlots = append(cd.SpecialSlots, sslot)
	}
	// Parse Slots
	pageSize := uint32(math.Pow(2, float64(cd.Header.PageSize)))
	for slot := uint32(0); slot < cd.Header.NCodeSlots; slot++ {
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
