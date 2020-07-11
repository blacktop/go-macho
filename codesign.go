package macho

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types/codesign"
)

// ParseCodeSignature parses the LC_CODE_SIGNATURE data
func ParseCodeSignature(cmddat []byte) (*CodeSignature, error) {
	r := bytes.NewReader(cmddat)

	cs := &CodeSignature{}

	csBlob := codesign.SuperBlob{}
	if err := binary.Read(r, binary.BigEndian, &csBlob); err != nil {
		return nil, err
	}

	csIndex := make([]codesign.BlobIndex, csBlob.Count)
	if err := binary.Read(r, binary.BigEndian, &csIndex); err != nil {
		return nil, err
	}

	for _, index := range csIndex {

		r.Seek(int64(index.Offset), io.SeekStart)

		switch index.Type {
		case codesign.CSSLOT_CODEDIRECTORY:
			fallthrough
		case codesign.CSSLOT_ALTERNATE_CODEDIRECTORIES:
			if err := binary.Read(r, binary.BigEndian, &cs.CodeDirectory); err != nil {
				return nil, err
			}
			// TODO parse all the cdhashs
			switch cs.CodeDirectory.Version {
			case codesign.SUPPORTS_SCATTER:
				if cs.CodeDirectory.ScatterOffset > 0 {
					r.Seek(int64(index.Offset+cs.CodeDirectory.ScatterOffset), io.SeekStart)
					scatter := codesign.Scatter{}
					if err := binary.Read(r, binary.BigEndian, &scatter); err != nil {
						return nil, err
					}
					fmt.Printf("%#v\n", scatter)
				}
			case codesign.SUPPORTS_TEAMID:
				r.Seek(int64(index.Offset+cs.CodeDirectory.TeamOffset), io.SeekStart)
				teamID, err := bufio.NewReader(r).ReadString('\x00')
				if err != nil {
					return nil, fmt.Errorf("failed to read SUPPORTS_TEAMID at: %d: %v", index.Offset+cs.CodeDirectory.TeamOffset, err)
				}
				cs.TeamID = strings.Trim(teamID, "\x00")
			case codesign.SUPPORTS_CODELIMIT64:
				// TODO 🤷‍♂️
			case codesign.SUPPORTS_EXECSEG:
				// TODO 🤷‍♂️
			default:
				fmt.Printf("Unknown code directory version 0x%x, please notify author\n", cs.CodeDirectory.Version)
			}
			r.Seek(int64(index.Offset+cs.CodeDirectory.IdentOffset), io.SeekStart)
			id, err := bufio.NewReader(r).ReadString('\x00')
			if err != nil {
				return nil, fmt.Errorf("failed to read CodeDirectory ID at: %d: %v", index.Offset+cs.CodeDirectory.IdentOffset, err)
			}
			cs.ID = id
		case codesign.CSSLOT_REQUIREMENTS:
			var err error
			req := codesign.Requirement{}
			csReqBlob := codesign.RequirementsBlob{}
			if err := binary.Read(r, binary.BigEndian, &csReqBlob); err != nil {
				return nil, err
			}
			req.RequirementsBlob = csReqBlob
			reqData := make([]byte, int(csReqBlob.Length)-binary.Size(codesign.RequirementsBlob{}))
			if err := binary.Read(r, binary.BigEndian, &reqData); err != nil {
				return nil, err
			}
			rqr := bytes.NewReader(reqData)
			var reqs codesign.Requirements
			if rqr.Len() >= binary.Size(reqs) {
				if err := binary.Read(rqr, binary.BigEndian, &reqs); err != nil {
					return nil, err
				}
				req.Requirements = reqs
			} else {
				var reqType uint32
				if err := binary.Read(rqr, binary.BigEndian, &reqType); err != nil {
					// return nil, err
					fmt.Printf("Got weird cs.Requirements: %#v\n", cs.Requirements)
				}
				req.Requirements.Type = codesign.RequirementType(reqType)
				req.Detail = "empty requirement set"
			}
			req.Detail, err = codesign.ParseRequirements(rqr, reqs)
			if err != nil {
				return nil, err
			}
			cs.Requirements = append(cs.Requirements, req)
		case codesign.CSSLOT_ENTITLEMENTS:
			entBlob := codesign.Blob{}
			if err := binary.Read(r, binary.BigEndian, &entBlob); err != nil {
				return nil, err
			}
			plistData := make([]byte, entBlob.Length-8)
			if err := binary.Read(r, binary.BigEndian, &plistData); err != nil {
				return nil, err
			}
			cs.Entitlements = string(plistData)
		case codesign.CSSLOT_CMS_SIGNATURE:
			cmsBlob := codesign.Blob{}
			if err := binary.Read(r, binary.BigEndian, &cmsBlob); err != nil {
				return nil, err
			}
			cmsData := make([]byte, cmsBlob.Length)
			if err := binary.Read(r, binary.BigEndian, &cmsData); err != nil {
				return nil, err
			}
			// NOTE: openssl pkcs7 -inform DER -in <cmsData> -print_certs -text -noout
			cs.CMSSignature = cmsData
		default:
			fmt.Printf("Found unsupported codesign slot %s, please notify author\n", index.Type)
		}
	}
	return cs, nil
}
