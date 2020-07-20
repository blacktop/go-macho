package codesign

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/blacktop/go-macho/pkg/codesign/types"
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
			if err := binary.Read(r, binary.BigEndian, &cs.CodeDirectory); err != nil {
				return nil, err
			}
			// TODO parse all the cdhashs
			switch cs.CodeDirectory.Version {
			case types.SUPPORTS_SCATTER:
				if cs.CodeDirectory.ScatterOffset > 0 {
					r.Seek(int64(index.Offset+cs.CodeDirectory.ScatterOffset), io.SeekStart)
					scatter := types.Scatter{}
					if err := binary.Read(r, binary.BigEndian, &scatter); err != nil {
						return nil, err
					}
					fmt.Printf("%#v\n", scatter)
				}
			case types.SUPPORTS_TEAMID:
				r.Seek(int64(index.Offset+cs.CodeDirectory.TeamOffset), io.SeekStart)
				teamID, err := bufio.NewReader(r).ReadString('\x00')
				if err != nil {
					return nil, fmt.Errorf("failed to read SUPPORTS_TEAMID at: %d: %v", index.Offset+cs.CodeDirectory.TeamOffset, err)
				}
				cs.TeamID = strings.Trim(teamID, "\x00")
			case types.SUPPORTS_CODELIMIT64:
				// TODO 🤷‍♂️
			case types.SUPPORTS_EXECSEG:
				// TODO 🤷‍♂️
			default:
				fmt.Printf("Unknown code directory version 0x%x, please notify author\n", cs.CodeDirectory.Version)
			}
			// Parse Indentity
			r.Seek(int64(index.Offset+cs.CodeDirectory.IdentOffset), io.SeekStart)
			id, err := bufio.NewReader(r).ReadString('\x00')
			if err != nil {
				return nil, fmt.Errorf("failed to read CodeDirectory ID at: %d: %v", index.Offset+cs.CodeDirectory.IdentOffset, err)
			}
			cs.ID = id
			// Parse Special Slots
			r.Seek(int64(index.Offset+cs.CodeDirectory.HashOffset-(cs.CodeDirectory.NSpecialSlots*uint32(cs.CodeDirectory.HashSize))), io.SeekStart)
			hash := make([]byte, cs.CodeDirectory.HashSize)
			for slot := cs.CodeDirectory.NSpecialSlots; slot > 0; slot-- {
				if err := binary.Read(r, binary.BigEndian, &hash); err != nil {
					return nil, err
				}
				if !bytes.Equal(hash, make([]byte, cs.CodeDirectory.HashSize)) {
					fmt.Printf("Special Slot   %d %s:\t%x\n", slot, types.SlotType(slot), hash)
				} else {
					fmt.Printf("Special Slot   %d %s:\tNot Bound\n", slot, types.SlotType(slot))
				}
			}
			pageSize := uint32(math.Pow(2, float64(cs.CodeDirectory.PageSize)))
			// Parse Slots
			for slot := uint32(0); slot < cs.CodeDirectory.NCodeSlots; slot++ {
				if err := binary.Read(r, binary.BigEndian, &hash); err != nil {
					return nil, err
				}
				if bytes.Equal(hash, types.NULL_PAGE_SHA256_HASH) && cs.CodeDirectory.HashType == types.HASHTYPE_SHA256 {
					fmt.Printf("Slot   %d (File page @0x%04X):\tNULL PAGE HASH\n", slot, slot*pageSize)
				} else {
					fmt.Printf("Slot   %d (File page @0x%04X):\t%x\n", slot, slot*pageSize, hash)
				}
			}
		case types.CSSLOT_REQUIREMENTS:
			// TODO find out if there can be more than one requirement(s)
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
