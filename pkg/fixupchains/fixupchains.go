package fixupchains

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Parse parses a LC_DYLD_CHAINED_FIXUPS load command
func Parse(lcdat *bytes.Reader, sr *io.SectionReader, bo binary.ByteOrder) (*DyldChainedFixups, error) {

	dcf := &DyldChainedFixups{}

	if err := binary.Read(lcdat, bo, &dcf.DyldChainedFixupsHeader); err != nil {
		return nil, err
	}

	lcdat.Seek(int64(dcf.DyldChainedFixupsHeader.StartsOffset), io.SeekStart)

	var segCount uint32
	if err := binary.Read(lcdat, bo, &segCount); err != nil {
		return nil, err
	}

	dcf.Starts = make([]DyldChainedStarts, segCount)
	segInfoOffsets := make([]uint32, segCount)
	if err := binary.Read(lcdat, bo, &segInfoOffsets); err != nil {
		return nil, err
	}

	for segIdx, segInfoOffset := range segInfoOffsets {
		if segInfoOffset == 0 {
			continue
		}

		lcdat.Seek(int64(dcf.DyldChainedFixupsHeader.StartsOffset+segInfoOffset), io.SeekStart)
		if err := binary.Read(lcdat, bo, &dcf.Starts[segIdx].DyldChainedStartsInSegment); err != nil {
			return nil, err
		}

		dcf.Starts[segIdx].PageStarts = make([]DCPtrStart, dcf.Starts[segIdx].DyldChainedStartsInSegment.PageCount)
		if err := binary.Read(lcdat, bo, &dcf.Starts[segIdx].PageStarts); err != nil {
			return nil, err
		}

		for pageIndex := uint16(0); pageIndex < dcf.Starts[segIdx].DyldChainedStartsInSegment.PageCount; pageIndex++ {
			offsetInPage := dcf.Starts[segIdx].PageStarts[pageIndex]

			if offsetInPage == DYLD_CHAINED_PTR_START_NONE {
				continue
			}

			if offsetInPage&DYLD_CHAINED_PTR_START_MULTI != 0 {
				// 32-bit chains which may need multiple starts per page
				overflowIndex := offsetInPage & ^DYLD_CHAINED_PTR_START_MULTI
				chainEnd := false
				for !chainEnd {
					chainEnd = (dcf.Starts[segIdx].PageStarts[overflowIndex]&DYLD_CHAINED_PTR_START_LAST != 0)
					offsetInPage = (dcf.Starts[segIdx].PageStarts[overflowIndex] & ^DYLD_CHAINED_PTR_START_LAST)
					if err := dcf.walkDcFixupChain(sr, bo, segIdx, pageIndex, offsetInPage); err != nil {
						return nil, err
					}
					overflowIndex++
				}

			} else {
				// one chain per page
				if err := dcf.walkDcFixupChain(sr, bo, segIdx, pageIndex, offsetInPage); err != nil {
					return nil, err
				}
			}
		}
	}

	// Parse Imports
	dcf.parseImports(lcdat, bo)

	return dcf, nil
}

func (dcf *DyldChainedFixups) walkDcFixupChain(sr *io.SectionReader, bo binary.ByteOrder, segIdx int, pageIndex uint16, offsetInPage DCPtrStart) error {

	var dcPtr uint32
	var dcPtr64 uint64
	var next uint64

	chainEnd := false
	pageContentStart := dcf.Starts[segIdx].DyldChainedStartsInSegment.SegmentOffset + uint64(pageIndex*dcf.Starts[segIdx].DyldChainedStartsInSegment.PageSize)

	for !chainEnd {
		fixupLocation := pageContentStart + uint64(offsetInPage) + next
		sr.Seek(int64(fixupLocation), io.SeekStart)

		switch dcf.Starts[segIdx].DyldChainedStartsInSegment.PointerFormat {
		case DYLD_CHAINED_PTR_32:
			if err := binary.Read(sr, bo, &dcPtr); err != nil {
				return err
			}
			if Generic32IsBind(dcPtr) {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtr32Bind{
					Pointer: dcPtr,
					Fixup:   fixupLocation,
				})
			} else {
				dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtr32Rebase{
					Pointer: dcPtr,
					Fixup:   fixupLocation,
				})
			}
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * 4
		case DYLD_CHAINED_PTR_32_CACHE:
			if err := binary.Read(sr, bo, &dcPtr); err != nil {
				return err
			}
			dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtr32CacheRebase{
				Pointer: dcPtr,
				Fixup:   fixupLocation,
			})
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * 4
		case DYLD_CHAINED_PTR_32_FIRMWARE:
			if err := binary.Read(sr, bo, &dcPtr); err != nil {
				return err
			}
			dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtr32FirmwareRebase{
				Pointer: dcPtr,
				Fixup:   fixupLocation,
			})
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * 4
		case DYLD_CHAINED_PTR_64: // target is vmaddr
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			if Generic64IsBind(dcPtr64) {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtr64Bind{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else {
				dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtr64Rebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			}
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * 4
		case DYLD_CHAINED_PTR_64_OFFSET: // target is vm offset
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtr64RebaseOffset{
				Pointer: dcPtr64,
				Fixup:   fixupLocation,
			})
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * 4
		case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtr64KernelCacheRebase{
				Pointer: dcPtr64,
				Fixup:   fixupLocation,
			})
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * 4
		case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: // stride 1, x86_64 kernel caches
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtr64KernelCacheRebase{
				Pointer: dcPtr64,
				Fixup:   fixupLocation,
			})
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64)
		case DYLD_CHAINED_PTR_ARM64E_KERNEL: // stride 4, unauth target is vm offset
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtrArm64eBind{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtrArm64eAuthBind{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * 4
		case DYLD_CHAINED_PTR_ARM64E_FIRMWARE: // stride 4, unauth target is vmaddr
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtrArm64eBind{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtrArm64eAuthBind{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * 4
		case DYLD_CHAINED_PTR_ARM64E: // stride 8, unauth target is vmaddr
			fallthrough
		case DYLD_CHAINED_PTR_ARM64E_USERLAND: // stride 8, unauth target is vm offset
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtrArm64eBind{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Rebases = append(dcf.Starts[segIdx].Rebases, DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtrArm64eAuthBind{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * 8
		case DYLD_CHAINED_PTR_ARM64E_USERLAND24: // stride 8, unauth target is vm offset, 24-bit bind
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			if DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtrArm64eAuthBind24{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Starts[segIdx].Binds = append(dcf.Starts[segIdx].Binds, DyldChainedPtrArm64eBind24{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				})
			} else {
				return fmt.Errorf("unknown DYLD_CHAINED_PTR_ARM64E_USERLAND24 pointer typr 0x%04X", dcPtr64)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * 8
		default:
			return fmt.Errorf("unknown pointer format 0x%04X", dcf.Starts[segIdx].DyldChainedStartsInSegment.PointerFormat)
		}
	}

	return nil
}

func (dcf *DyldChainedFixups) parseImports(r *bytes.Reader, bo binary.ByteOrder) error {

	var imports []Import

	r.Seek(int64(dcf.ImportsOffset), io.SeekStart)

	switch dcf.DyldChainedFixupsHeader.ImportsFormat {
	case DC_IMPORT:
		ii := make([]DyldChainedImport, dcf.ImportsCount)
		if err := binary.Read(r, bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	case DC_IMPORT_ADDEND:
		ii := make([]DyldChainedImportAddend, dcf.ImportsCount)
		if err := binary.Read(r, bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	case DC_IMPORT_ADDEND64:
		ii := make([]DyldChainedImportAddend64, dcf.ImportsCount)
		if err := binary.Read(r, bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	}

	symbolsPool := io.NewSectionReader(r, int64(dcf.SymbolsOffset), r.Size()-int64(dcf.SymbolsOffset))
	for _, i := range imports {
		symbolsPool.Seek(int64(i.NameOffset()), io.SeekStart)
		s, err := bufio.NewReader(symbolsPool).ReadString('\x00')
		if err != nil {
			return fmt.Errorf("failed to read string at: %d: %v", uint64(dcf.SymbolsOffset)+i.NameOffset(), err)
		}
		dcf.Imports = append(dcf.Imports, DcfImport{
			Name:   strings.Trim(s, "\x00"),
			Import: i,
		})
	}

	return nil
}
