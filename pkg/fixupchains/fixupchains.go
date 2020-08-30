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
	segInfoOffsets := make([]uint32, segCount)
	if err := binary.Read(lcdat, bo, &segInfoOffsets); err != nil {
		return nil, err
	}

	for _, segInfoOffset := range segInfoOffsets {
		if segInfoOffset == 0 {
			continue
		}
		lcdat.Seek(int64(dcf.DyldChainedFixupsHeader.StartsOffset+segInfoOffset), io.SeekStart)
		if err := binary.Read(lcdat, bo, &dcf.DyldChainedStartsInSegment); err != nil {
			return nil, err
		}

		pageStarts := make([]DCPtrStart, dcf.DyldChainedStartsInSegment.PageCount)
		if err := binary.Read(lcdat, bo, &pageStarts); err != nil {
			return nil, err
		}
		for pageIndex := uint16(0); pageIndex < dcf.DyldChainedStartsInSegment.PageCount; pageIndex++ {
			offsetInPage := pageStarts[pageIndex]
			if offsetInPage == DYLD_CHAINED_PTR_START_NONE {
				continue
			}
			// TODO: handle this case
			if offsetInPage&DYLD_CHAINED_PTR_START_MULTI != 0 {
				// 32-bit chains which may need multiple starts per page
				overflowIndex := offsetInPage & ^DYLD_CHAINED_PTR_START_MULTI
				chainEnd := false
				// for !stopped && !chainEnd {
				for !chainEnd {
					chainEnd = (pageStarts[overflowIndex]&DYLD_CHAINED_PTR_START_LAST != 0)
					offsetInPage = (pageStarts[overflowIndex] & ^DYLD_CHAINED_PTR_START_LAST)
					// if err := f.walkDcFixupChain(dcf, pageContentStart, offsetInPage); err != nil {
					// 	return nil, err
					// }
					// if walkChain(diag, segInfo, pageIndex, offsetInPage, notifyNonPointers, handler) {
					//	stopped = true
					// }
					overflowIndex++
				}
			} else {
				// one chain per page
				pageContentStart := dcf.DyldChainedStartsInSegment.SegmentOffset + uint64(pageIndex*dcf.DyldChainedStartsInSegment.PageSize)
				if err := walkDcFixupChain(sr, bo, dcf, pageContentStart, offsetInPage); err != nil {
					return nil, err
				}
			}
		}
	}

	// Parse Imports
	parseDcFixupImports(dcf, lcdat, bo)

	return dcf, nil
}

func walkDcFixupChain(sr *io.SectionReader, bo binary.ByteOrder, dcf *DyldChainedFixups, pageContentStart uint64, offsetInPage DCPtrStart) error {

	var dcPtr uint32
	var dcPtr64 uint64
	var next uint64

	chainEnd := false

	for !chainEnd {
		sr.Seek(int64(pageContentStart+uint64(offsetInPage)+next), io.SeekStart)

		switch dcf.DyldChainedStartsInSegment.PointerFormat {
		case DYLD_CHAINED_PTR_32:
			if err := binary.Read(sr, bo, &dcPtr); err != nil {
				return err
			}
			if Generic32IsBind(dcPtr) {
				dcf.Binds = append(dcf.Binds, DyldChainedPtr32Bind(dcPtr))
			} else {
				dcf.Rebases = append(dcf.Rebases, DyldChainedPtr32Rebase(dcPtr))
			}
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * 4
		case DYLD_CHAINED_PTR_32_CACHE:
			if err := binary.Read(sr, bo, &dcPtr); err != nil {
				return err
			}
			dcf.Rebases = append(dcf.Rebases, DyldChainedPtr32CacheRebase(dcPtr))
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * 4
		case DYLD_CHAINED_PTR_32_FIRMWARE:
			if err := binary.Read(sr, bo, &dcPtr); err != nil {
				return err
			}
			dcf.Rebases = append(dcf.Rebases, DyldChainedPtr32FirmwareRebase(dcPtr))
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * 4
		case DYLD_CHAINED_PTR_64: // target is vmaddr
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			if Generic64IsBind(dcPtr64) {
				dcf.Binds = append(dcf.Binds, DyldChainedPtr64Bind(dcPtr64))
			} else {
				dcf.Rebases = append(dcf.Rebases, DyldChainedPtr64Rebase(dcPtr64))
			}
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * 4
		case DYLD_CHAINED_PTR_64_OFFSET: // target is vm offset
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			dcf.Rebases = append(dcf.Rebases, DyldChainedPtr64RebaseOffset(dcPtr64))
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * 4
		case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			dcf.Rebases = append(dcf.Rebases, DyldChainedPtr64KernelCacheRebase(dcPtr64))
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * 4
		case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: // stride 1, x86_64 kernel caches
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			dcf.Rebases = append(dcf.Rebases, DyldChainedPtr64KernelCacheRebase(dcPtr64))
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64)
		case DYLD_CHAINED_PTR_ARM64E_KERNEL: // stride 4, unauth target is vm offset
			if err := binary.Read(sr, bo, &dcPtr64); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Rebases = append(dcf.Rebases, DyldChainedPtrArm64eRebase(dcPtr64))
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Binds = append(dcf.Binds, DyldChainedPtrArm64eBind(dcPtr64))
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				dcf.Rebases = append(dcf.Rebases, DyldChainedPtrArm64eAuthRebase(dcPtr64))
			} else {
				dcf.Binds = append(dcf.Binds, DyldChainedPtrArm64eAuthBind(dcPtr64))
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
				dcf.Rebases = append(dcf.Rebases, DyldChainedPtrArm64eRebase(dcPtr64))
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Binds = append(dcf.Binds, DyldChainedPtrArm64eBind(dcPtr64))
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				dcf.Rebases = append(dcf.Rebases, DyldChainedPtrArm64eAuthRebase(dcPtr64))
			} else {
				dcf.Binds = append(dcf.Binds, DyldChainedPtrArm64eAuthBind(dcPtr64))
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
				dcf.Rebases = append(dcf.Rebases, DyldChainedPtrArm64eRebase(dcPtr64))
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Binds = append(dcf.Binds, DyldChainedPtrArm64eBind(dcPtr64))
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				dcf.Rebases = append(dcf.Rebases, DyldChainedPtrArm64eAuthRebase(dcPtr64))
			} else {
				dcf.Binds = append(dcf.Binds, DyldChainedPtrArm64eAuthBind(dcPtr64))
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
				dcf.Binds = append(dcf.Binds, DyldChainedPtrArm64eAuthBind24(dcPtr64))
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				dcf.Binds = append(dcf.Binds, DyldChainedPtrArm64eBind24(dcPtr64))
			} else {
				return fmt.Errorf("unknown DYLD_CHAINED_PTR_ARM64E_USERLAND24 pointer typr 0x%04X", dcPtr64)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * 8
		default:
			return fmt.Errorf("unknown pointer format 0x%04X", dcf.DyldChainedStartsInSegment.PointerFormat)
		}
	}

	return nil
}

func parseDcFixupImports(dcf *DyldChainedFixups, r *bytes.Reader, bo binary.ByteOrder) error {
	switch dcf.DyldChainedFixupsHeader.ImportsFormat {
	case DC_IMPORT:
		r.Seek(int64(dcf.ImportsOffset), io.SeekStart)
		imports := make([]DyldChainedImport, dcf.ImportsCount)
		if err := binary.Read(r, bo, &imports); err != nil {
			return err
		}
		symbolsPool := io.NewSectionReader(r, int64(dcf.SymbolsOffset), r.Size()-int64(dcf.SymbolsOffset))
		for _, i := range imports {
			symbolsPool.Seek(int64(i.NameOffset()), io.SeekStart)
			s, err := bufio.NewReader(symbolsPool).ReadString('\x00')
			if err != nil {
				return fmt.Errorf("failed to read string at: %d: %v", dcf.SymbolsOffset+i.NameOffset(), err)
			}
			dcf.Imports = append(dcf.Imports, DcfImport{
				Name:    strings.Trim(s, "\x00"),
				Pointer: i,
			})
		}
	case DC_IMPORT_ADDEND:
		r.Seek(int64(dcf.ImportsOffset), io.SeekStart)
		imports := make([]DyldChainedImportAddend, dcf.ImportsCount)
		if err := binary.Read(r, bo, &imports); err != nil {
			return err
		}
		symbolsPool := io.NewSectionReader(r, int64(dcf.SymbolsOffset), r.Size()-int64(dcf.SymbolsOffset))
		for _, i := range imports {
			symbolsPool.Seek(int64(i.Import.NameOffset()), io.SeekStart)
			s, err := bufio.NewReader(symbolsPool).ReadString('\x00')
			if err != nil {
				return fmt.Errorf("failed to read string at: %d: %v", dcf.SymbolsOffset+i.Import.NameOffset(), err)
			}
			dcf.Imports = append(dcf.Imports, DcfImport{
				Name:    strings.Trim(s, "\x00"),
				Pointer: i,
			})
		}
	case DC_IMPORT_ADDEND64:
		r.Seek(int64(dcf.ImportsOffset), io.SeekStart)
		imports := make([]DyldChainedImportAddend64, dcf.ImportsCount)
		if err := binary.Read(r, bo, &imports); err != nil {
			return err
		}
		symbolsPool := io.NewSectionReader(r, int64(dcf.SymbolsOffset), r.Size()-int64(dcf.SymbolsOffset))
		for _, i := range imports {
			symbolsPool.Seek(int64(i.Import.NameOffset()), io.SeekStart)
			s, err := bufio.NewReader(symbolsPool).ReadString('\x00')
			if err != nil {
				return fmt.Errorf("failed to read string at: %d: %v", uint64(dcf.SymbolsOffset)+i.Import.NameOffset(), err)
			}
			dcf.Imports = append(dcf.Imports, DcfImport{
				Name:    strings.Trim(s, "\x00"),
				Pointer: i,
			})
		}
	}

	return nil
}
