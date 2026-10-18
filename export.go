package macho

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/blacktop/go-macho/pkg/codesign"
	ctypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
)

type segInfo struct {
	Start     uint64
	End       uint64
	VirtStart uint64
	VirtEnd   uint64
}

func (i segInfo) Size(virt bool) uint64 {
	if virt {
		return i.VirtEnd - i.VirtStart
	} else {
		return i.End - i.Start
	}
}

type segMapInfo struct {
	Name       string
	Old        segInfo
	New        segInfo
	OrigMemsz  uint64
	OrigFilesz uint64
}

func (i segMapInfo) LessThan(o segMapInfo) bool {
	return i.Old.Start < o.Old.Start
}

func (i *segMapInfo) Move(offset uint64) {
	i.New.Start += offset
	i.New.End += offset
	i.New.VirtStart += offset
	i.New.VirtEnd += offset
}

func (i *segMapInfo) Grow(increase uint64) {
	i.New.End += increase
	i.New.VirtEnd += increase
}

type exportSegMap []segMapInfo

func (m exportSegMap) Len() int {
	return len(m)
}

func (m exportSegMap) Less(i, j int) bool {
	return m[i].LessThan(m[j])
}

func (m exportSegMap) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}

// RefreshLayout moves segments until there is no overlap.
func (m exportSegMap) RefreshLayout() {
	var lastOffset uint64 = 0
	for idx := range m {
		segInfo := &m[idx]
		if segInfo.New.Start < lastOffset {
			segInfo.Move(lastOffset - segInfo.New.Start)
		}
		lastOffset = segInfo.New.End
	}
}

// RemapOffset maps a file offset of the source image into the exported image.
// A segment containing the offset wins over one that merely ends at it: cache
// images pack segments back to back, so a segment's end offset is frequently
// the start of an unrelated segment.
func (m exportSegMap) RemapOffset(offset uint64) (uint64, error) {
	for _, segInfo := range m {
		if segInfo.Old.Start <= offset && offset < segInfo.Old.End {
			return segInfo.New.Start + (offset - segInfo.Old.Start), nil
		}
	}
	for _, segInfo := range m {
		if segInfo.Old.Start <= offset && offset <= segInfo.Old.End {
			return segInfo.New.Start + (offset - segInfo.Old.Start), nil
		}
	}
	return 0, fmt.Errorf("failed to remap offset %#x", offset)
}

// RemapAddress maps a VM address of the source image into the exported image.
// As with offsets, a containing segment wins over one that ends at the address
// (which only identifies one-past-the-end references).
// RemapLinkeditOffset remaps the file offset of LINKEDIT data. The segments
// of a shared cache image live in different subcache files, so their file
// offset ranges can overlap; LINKEDIT data must be resolved in __LINKEDIT.
func (m exportSegMap) RemapLinkeditOffset(offset uint64) (uint64, error) {
	if linkedit, ok := m.Lookup("__LINKEDIT"); ok && linkedit.Old.Start <= offset && offset <= linkedit.Old.End {
		return linkedit.New.Start + (offset - linkedit.Old.Start), nil
	}
	return m.RemapOffset(offset)
}

func (m exportSegMap) RemapAddress(address uint64) (uint64, error) {
	for _, segInfo := range m {
		if segInfo.Old.VirtStart <= address && address < segInfo.Old.VirtEnd {
			return segInfo.New.VirtStart + (address - segInfo.Old.VirtStart), nil
		}
	}
	for _, segInfo := range m {
		if segInfo.Old.VirtStart <= address && address <= segInfo.Old.VirtEnd {
			return segInfo.New.VirtStart + (address - segInfo.Old.VirtStart), nil
		}
	}
	return 0, fmt.Errorf("failed to remap address %#x", address)
}

func (m exportSegMap) RemapSeg(name string, offset uint64) (uint64, uint64, error) {
	for _, segInfo := range m {
		if segInfo.Name == name {
			return segInfo.New.Start + (offset - segInfo.Old.Start), (segInfo.New.End - segInfo.New.Start), nil
		}
	}
	return 0, 0, fmt.Errorf("failed to remap offset %#x", offset)
}

func (m exportSegMap) Lookup(name string) (segMapInfo, bool) {
	for _, info := range m {
		if info.Name == name {
			return info, true
		}
	}
	return segMapInfo{}, false
}

func pageAlign(off, align uint64) uint64 {
	if (off % align) != 0 {
		off += align - (off % align)
	}
	return off
}

// pointerAlignPad returns the number of zero bytes needed to
// align currentLen up to the next multiple of ptrSize.
func pointerAlignPad(currentLen int, ptrSize uint64) int {
	rem := uint64(currentLen) % ptrSize
	if rem == 0 {
		return 0
	}
	return int(ptrSize - rem)
}

func (f *File) textSegmentFirstSectionRelOff(inCache bool) (uint64, error) {
	textSeg := f.Segment("__TEXT")
	if textSeg == nil {
		return 0, nil
	}
	for i := uint32(0); i < textSeg.Nsect; i++ {
		idx := uint64(textSeg.Firstsect) + uint64(i)
		if idx >= uint64(len(f.Sections)) {
			return 0, fmt.Errorf("__TEXT section index %d out of range", idx)
		}
		sec := f.Sections[int(idx)]
		if sec.Offset == 0 {
			continue
		}
		if inCache {
			if sec.Addr < textSeg.Addr {
				return 0, fmt.Errorf("__TEXT section %s address %#x precedes segment address %#x", sec.Name, sec.Addr, textSeg.Addr)
			}
			return sec.Addr - textSeg.Addr, nil
		}
		if uint64(sec.Offset) < textSeg.Offset {
			return 0, fmt.Errorf("__TEXT section %s offset %#x precedes segment offset %#x", sec.Name, sec.Offset, textSeg.Offset)
		}
		return uint64(sec.Offset) - textSeg.Offset, nil
	}
	return 0, nil
}

func textSegmentWriteStart(firstSectionRelOff, endOfLoadsOffset, dataLen uint64) (uint64, error) {
	dataStart := firstSectionRelOff
	if endOfLoadsOffset > dataStart {
		dataStart = endOfLoadsOffset
	}
	if dataStart > dataLen {
		return 0, fmt.Errorf("__TEXT data start %#x exceeds segment data length %#x", dataStart, dataLen)
	}
	return dataStart, nil
}

// ExportOption configures File.Export.
type ExportOption func(*exportOptions)

type exportOptions struct {
	references []*types.SplitInfoEntry
}

// WithReferences passes the split-segment references of a cached image, e.g.
// recovered from a kernel collection. With them, Export packs the segments
// into a contiguous layout at baseAddress, rewrites the references and
// recreates the image's chained fixups. Without them, segments keep their
// cache addresses.
func WithReferences(references []*types.SplitInfoEntry) ExportOption {
	return func(o *exportOptions) { o.references = references }
}

// Export exports an in-memory or cached dylib|kext MachO to a file
// This should not alter the file itself.
func (f *File) Export(path string, dcf *fixupchains.DyldChainedFixups, baseAddress uint64, locals []Symbol, opts ...ExportOption) (err error) {
	var options exportOptions
	for _, opt := range opts {
		opt(&options)
	}
	references := options.references
	pack := len(references) > 0
	// First Phase: Building of a Segment Map
	segMap, fileHeader, loads, err := f.createExportFileLayout(baseAddress, pack)
	if err != nil {
		return err
	}
	// The file layout is fixed now!
	// No segment shifting below!
	// No new load commands, etc
	// Only the last segment can grow (LINKEDIT)

	// Second Phase: Writing the content
	newFileData, exportFile, err := f.createExportFile(segMap, fileHeader, loads)
	if err != nil {
		return err
	}

	// Third Phase: Patching the content
	newFileData, err = f.patchExportFile(segMap, newFileData, exportFile, dcf, locals, references, pack)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", path, err)
	}

	if err := os.WriteFile(path, newFileData, 0755); err != nil {
		return fmt.Errorf("failed to write exported MachO to file %s: %w", path, err)
	}

	return nil
}

func (f *File) createExportFileLayout(baseAddress uint64, pack bool) (exportSegMap, *types.FileHeader, []Load, error) {
	// Initial Layout
	var segMap exportSegMap
	if pack {
		segMap = f.createContiguousSegmentMap(baseAddress)
		// Resize before cloning load commands so the exported section and
		// segment metadata include the generated auth stubs.
		f.resizeAuthStubs(segMap)
	} else {
		segMap = f.createCacheAddressSegmentMap()
	}

	// Copy Header
	var headerBuf bytes.Buffer
	err := f.FileHeader.Write(&headerBuf, f.ByteOrder)
	if err != nil {
		return nil, nil, nil, err
	}
	var fileHeader types.FileHeader
	if err := binary.Read(&headerBuf, f.ByteOrder, &fileHeader); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Copy Load Commands (currently no need to update fileHeader.SizeCommands)
	loads, err := f.optimizeLoadCommands(segMap, f.FileHeader.Flags.DylibInCache())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to optimize load commands: %w", err)
	}

	// Adjustments
	fileHeader.Flags &= 0x7FFFFFFF // remove in-cache bit
	if pack {
		loads = addDyldChainedFixupsLoad(&fileHeader, loads)
		loads = addSplitSegmentInfoLoad(&fileHeader, loads)
		loads = orderLoadsLikeLinker(loads)
	} else if f.FileHeader.Flags.DylibInCache() {
		// The cache's fixup chains are not reconstructed without references.
		loads = removeLoad(&fileHeader, loads, types.LC_DYLD_CHAINED_FIXUPS)
	}

	return segMap, &fileHeader, loads, nil
}

func (f *File) createExportFile(segMap exportSegMap, fileHeader *types.FileHeader, loads []Load) ([]byte, *File, error) {
	var buf bytes.Buffer
	// pre-allocate output buffer to avoid repeated doubling during writes
	if len(segMap) > 0 {
		buf.Grow(int(segMap[len(segMap)-1].New.End))
	}

	if err := fileHeader.Write(&buf, f.ByteOrder); err != nil {
		return nil, nil, fmt.Errorf("failed to write file header to buffer: %v", err)
	}

	if err := f.writeLoadCommands(&buf, loads); err != nil {
		return nil, nil, fmt.Errorf("failed to write load commands: %v", err)
	}
	endOfLoadsOffset := uint64(buf.Len())

	// Write out segment data to buffer
	for _, seg := range f.Segments() {
		smi, ok := segMap.Lookup(seg.Name)
		if !ok || seg.Filesz == 0 {
			continue
		}

		// pad buffer to this segment's expected start offset
		if uint64(buf.Len()) < smi.New.Start {
			if _, err := buf.Write(make([]byte, smi.New.Start-uint64(buf.Len()))); err != nil {
				return nil, nil, fmt.Errorf("failed to write pre-segment padding for %s: %v", seg.Name, err)
			}
		}

		sizeToCopy := min(smi.OrigFilesz, smi.New.Size(false))
		dat := make([]byte, sizeToCopy)
		if _, err := f.cr.ReadAtAddr(dat, seg.Addr); err != nil {
			return nil, nil, fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
		}

		if seg.Name == "__TEXT" {
			// write __TEXT data after the header+load commands we already wrote
			if _, err := buf.Write(dat[endOfLoadsOffset:]); err != nil {
				return nil, nil, fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
			}
		} else {
			if _, err := buf.Write(dat); err != nil {
				return nil, nil, fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
			}
		}

		// pad to segment's page-aligned end
		if uint64(buf.Len()) < smi.New.End {
			if _, err := buf.Write(make([]byte, smi.New.End-uint64(buf.Len()))); err != nil {
				return nil, nil, fmt.Errorf("failed to write post-segment padding for %s: %v", seg.Name, err)
			}
		}
	}

	data := buf.Bytes()
	exportFile, err := NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create export File: %w", err)
	}

	return data, exportFile, nil
}

func (f *File) patchExportFile(segMap exportSegMap, exportData []byte, exportFile *File, dcf *fixupchains.DyldChainedFixups, locals []Symbol, references []*types.SplitInfoEntry, pack bool) ([]byte, error) {
	inCache := f.FileHeader.Flags.DylibInCache()
	if !inCache {
		return exportData, nil
	}

	// The exported file re-reads its symbol table from the source LINKEDIT.
	// Keep names the caller corrected on f (e.g. renamings done by the cache
	// builder) so they reach the rebuilt symbol table.
	if f.Symtab != nil && exportFile.Symtab != nil && len(f.Symtab.Syms) == len(exportFile.Symtab.Syms) {
		for i := range exportFile.Symtab.Syms {
			exportFile.Symtab.Syms[i].Name = f.Symtab.Syms[i].Name
		}
	}

	var binds map[uint64]Symbol
	var rebases, others map[uint64]uint64
	var auths map[uint64]chainedFixupAuth
	if pack {
		// Create Auth Stubs
		if err := exportFile.writeAuthStubs(exportData); err != nil {
			return nil, err
		}

		// Patch relative references
		var err error
		binds, rebases, others, auths, err = exportFile.adjustReferences(segMap, exportData, locals, references)
		if err != nil {
			return nil, err
		}
		if err := exportFile.clearKmodInfoCacheFields(segMap, exportData, locals); err != nil {
			return nil, err
		}
		if err := exportFile.restoreFIPSHMAC(exportData); err != nil {
			return nil, err
		}
	}

	// Recreate LINKEDIT segment
	functionStarts, err := f.remappedFunctionStarts(segMap)
	if err != nil {
		return nil, err
	}
	exportData, err = exportFile.optimizeLinkedit(exportData, segMap, locals, references, binds, rebases, others, auths, functionStarts, pack)
	if err != nil {
		return nil, err
	}

	return exportData, nil
}

// restoreFIPSHMAC reproduces the kernel-collection builder's final FIPS seal:
// HMAC-SHA256 of the post-rewrite __text section with the one-byte key {0}.
func (f *File) restoreFIPSHMAC(exportData []byte) error {
	seal := f.Section("__TEXT", "__fips_hmacs")
	if seal == nil {
		return nil
	}
	text := f.Section("__TEXT", "__text")
	if text == nil {
		text = f.Section("__TEXT_EXEC", "__text")
	}
	if text == nil {
		return fmt.Errorf("cannot seal __fips_hmacs without a __text section")
	}
	if seal.Size < sha256.Size {
		return fmt.Errorf("__fips_hmacs is %d bytes; need at least %d", seal.Size, sha256.Size)
	}
	textEnd := uint64(text.Offset) + text.Size
	sealEnd := uint64(seal.Offset) + sha256.Size
	if textEnd > uint64(len(exportData)) || sealEnd > uint64(len(exportData)) {
		return fmt.Errorf("FIPS sections exceed exported data bounds")
	}
	mac := hmac.New(sha256.New, []byte{0})
	_, _ = mac.Write(exportData[text.Offset:textEnd])
	copy(exportData[seal.Offset:sealEnd], mac.Sum(nil))
	return nil
}

func (f *File) clearKmodInfoCacheFields(segMap exportSegMap, exportData []byte, extra ...[]Symbol) error {
	var candidates []Symbol
	if f.Symtab != nil {
		candidates = append(candidates, f.Symtab.Syms...)
	}
	// Stripped collections carry no _kmod_info symbol; callers pass it in.
	for _, syms := range extra {
		candidates = append(candidates, syms...)
	}
	for _, sym := range candidates {
		if sym.Name != "_kmod_info" || !sym.Type.IsDefinedInSection() {
			continue
		}
		address, err := segMap.RemapAddress(sym.Value)
		if err != nil {
			return fmt.Errorf("failed to remap _kmod_info at %#x: %w", sym.Value, err)
		}
		offset, err := f.GetOffset(address)
		if err != nil {
			return fmt.Errorf("failed to locate recovered _kmod_info: %w", err)
		}
		// kmutil fills address and size in the cached kmod_info. The
		// standalone KEXT stores zero for both 64-bit fields. kmod_info is
		// packed to 4-byte alignment, placing them at 0x9c and 0xa4.
		const cacheFieldsOffset = uint64(0x9c)
		const cacheFieldsSize = uint64(16)
		start := offset + cacheFieldsOffset
		end := start + cacheFieldsSize
		if end > uint64(len(exportData)) {
			return fmt.Errorf("_kmod_info cache fields exceed exported file size")
		}
		clear(exportData[start:end])
		return nil
	}
	return nil
}

// createCacheAddressSegmentMap keeps every segment at its cache address and
// only lays out the file offsets back to back.
func (f *File) createCacheAddressSegmentMap() exportSegMap {
	pgSz := f.pageSize()
	var fileMap exportSegMap
	var newSegOffset uint64
	for _, seg := range f.Segments() {
		fileMap = append(fileMap, segMapInfo{
			Name: seg.Name,
			Old: segInfo{
				Start:     seg.Offset,
				End:       seg.Offset + seg.Filesz,
				VirtStart: seg.Addr,
				VirtEnd:   seg.Addr + seg.Memsz,
			},
			New: segInfo{
				Start:     newSegOffset,
				End:       newSegOffset + pageAlign(seg.Filesz, pgSz),
				VirtStart: seg.Addr,
				VirtEnd:   seg.Addr + pageAlign(seg.Memsz, pgSz),
			},
			OrigMemsz:  seg.Memsz,
			OrigFilesz: seg.Filesz,
		})
		newSegOffset += pageAlign(seg.Filesz, pgSz)
	}
	return fileMap
}

func (f *File) createContiguousSegmentMap(baseAddress uint64) exportSegMap {
	pgSz := f.pageSize()
	var fileMap exportSegMap
	var newSegOffset uint64
	var newSegAddr uint64 = baseAddress
	for _, seg := range f.Segments() {
		segMap := segMapInfo{
			Name: seg.Name,
			Old: segInfo{
				Start:     seg.Offset,
				End:       seg.Offset + seg.Filesz,
				VirtStart: seg.Addr,
				VirtEnd:   seg.Addr + seg.Memsz,
			},
			New: segInfo{
				Start:     newSegOffset,
				End:       newSegOffset + pageAlign(seg.Filesz, pgSz),
				VirtStart: newSegAddr,
				VirtEnd:   newSegAddr + pageAlign(seg.Memsz, pgSz),
			},
			OrigMemsz:  seg.Memsz,
			OrigFilesz: seg.Filesz,
		}
		fileMap = append(fileMap, segMap)
		newSegOffset += pageAlign(seg.Filesz, pgSz)
		newSegAddr += pageAlign(seg.Memsz, pgSz)
	}
	return fileMap
}

func (f *File) CodeSign(config *codesign.Config) error {
	var cs *CodeSignature

	config.InitSlotHashes() // initialize slot hashes with default empty slot hashes

	config.IsMain = f.Type == types.MH_EXECUTE

	text := f.Segment("__TEXT")
	if text == nil {
		return fmt.Errorf("failed to find __TEXT segment")
	}
	config.TextOffset = uint64(text.Offset)
	config.TextSize = uint64(text.Filesz)

	// check if there is an embedded Info.plist
	if infoPlist, err := f.GetEmbeddedInfoPlist(); err == nil {
		config.InfoPlist = infoPlist
	}

	linkedit := f.Segment("__LINKEDIT")
	if linkedit == nil {
		return fmt.Errorf("failed to find __LINKEDIT segment")
	}

	if config.ResourceDirSlotHash != nil {
		config.SlotHashes.ResourceDir = config.ResourceDirSlotHash
	}

	if cs = f.CodeSignature(); cs != nil { // existing code signature
		// import settings from existing code signature
		if len(cs.CodeDirectories) > 0 {
			if config.ID == "" {
				config.ID = cs.CodeDirectories[0].ID
			}
			if config.TeamID == "" {
				config.TeamID = cs.CodeDirectories[0].TeamID
			}
			if config.Flags == ctypes.ADHOC {
				config.Flags &= ^ctypes.LINKER_SIGNED // remove linker signed flag TODO: should I do this?
			}
			if config.Entitlements == nil {
				config.Entitlements = []byte(cs.Entitlements)
			}
			if config.EntitlementsDER == nil {
				config.EntitlementsDER = []byte(cs.EntitlementsDER)
			}
			if config.SpecialSlots == nil {
				config.SpecialSlots = cs.CodeDirectories[0].SpecialSlots
			}
			if config.RuntimeVersion == 0 {
				if cs.CodeDirectories[0].Header.Runtime != 0 {
					config.RuntimeVersion = cs.CodeDirectories[0].Header.Runtime
				} else if bvs := f.BuildVersions(); len(bvs) > 0 {
					config.RuntimeVersion = bvs[0].Sdk
				} else if vm := f.VersionMin(); vm != nil {
					config.RuntimeVersion = vm.Sdk
				}
			}
		}
	} else { // create NEW code signature
		if config.ID == "" {
			return fmt.Errorf("you must supply an ID")
		}
		// infer runtime version from build or min version load commands if necessary
		if config.Flags&ctypes.RUNTIME != 0 {
			if config.RuntimeVersion == 0 {
				if bvs := f.BuildVersions(); len(bvs) > 0 {
					config.RuntimeVersion = bvs[0].Sdk
				} else if vm := f.VersionMin(); vm != nil {
					config.RuntimeVersion = vm.Sdk
				}
			}
		} else {
			config.RuntimeVersion = 0
		}
		cs = &CodeSignature{
			CodeSignatureCmd: types.CodeSignatureCmd{
				LoadCmd: types.LC_CODE_SIGNATURE,
				Len:     uint32(binary.Size(types.CodeSignatureCmd{})),
			},
		}
		cs.Offset = pointerAlign(uint32(linkedit.Offset + linkedit.Filesz))
		// add NEW codesignature load command
		f.AddLoad(cs)
		// refresh
		cs = f.CodeSignature()
	}

	config.CodeSize = uint64(cs.Offset)

	// cache __LINKEDIT data (up to but not including any existing code signature) for saving later.
	// if the actual data doesn't go up to a page boundary (because we're adding a new signature), pad it with zeroes
	ledata := make([]byte, uint64(cs.Offset)-linkedit.Offset)
	size := uint64(len(ledata))
	if size > linkedit.Filesz {
		size = linkedit.Filesz
	}
	if n, err := f.cr.ReadAtAddr(ledata[:size], linkedit.Addr); err != nil {
		return fmt.Errorf("failed to read __LINKEDIT data: read=%d, %v", n, err)
	}
	f.ledata = bytes.NewBuffer(ledata)

	// update __LINKEDIT segment sizes
	linkedit.Filesz = pageAlign(uint64(len(ledata))+codesign.EstimateCodeSignatureSize(config), f.pageSize())
	linkedit.Memsz = pageAlign(linkedit.Filesz, f.pageSize())
	// update LC_CODE_SIGNATURE size
	cs.Size = uint32((linkedit.Offset + linkedit.Filesz) - uint64(cs.Offset))

	// read data to be signed; pad to beginning of code signature if necessary (in case we added a signature to a not-page-aligned-size file)
	data := make([]byte, cs.Offset)
	if _, err := f.ReadAt(data[:linkedit.Offset+size], 0); err != nil {
		return fmt.Errorf("failed to read codesign data: %v", err)
	}
	// write modified file header and load commands (including __LINKEDIT and CodeSignature), since they are covered by hashes
	var buf bytes.Buffer
	if err := f.FileHeader.Write(&buf, f.ByteOrder); err != nil {
		return fmt.Errorf("failed to write updated header: %v", err)
	}
	if err := f.writeLoadCommands(&buf, f.Loads); err != nil {
		return fmt.Errorf("failed to write updated load commands: %v", err)
	}
	copy(data, buf.Bytes())

	// sign data and add it to the new LINKEDIT segment
	csdata, err := codesign.Sign(bytes.NewReader(data), config)
	if err != nil {
		return fmt.Errorf("failed to create codesignature data: %v", err)
	}
	if _, err := f.ledata.Write(csdata); err != nil {
		return fmt.Errorf("failed to write codesign data to linkedit segment data: %v", err)
	}

	if linkedit.Filesz < uint64(f.ledata.Len()) {
		return fmt.Errorf("new linkedit data is larger than expected")
	} else if linkedit.Filesz > uint64(f.ledata.Len()) { // pad with zeros
		if _, err := f.ledata.Write(make([]byte, linkedit.Filesz-uint64(f.ledata.Len()))); err != nil {
			return fmt.Errorf("failed to write linkedit segment padding: %v", err)
		}
	}

	return nil
}

func (f *File) Save(outpath string) error {
	var buf bytes.Buffer
	if err := f.SaveBuffer(&buf); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outpath), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", outpath, err)
	}

	if err := os.WriteFile(outpath, buf.Bytes(), 0755); err != nil {
		return fmt.Errorf("failed to save MachO to file %s: %w", outpath, err)
	}

	return nil
}

func (f *File) SaveBuffer(buf *bytes.Buffer) error {
	if err := f.FileHeader.Write(buf, f.ByteOrder); err != nil {
		return fmt.Errorf("failed to write file header to buffer: %v", err)
	}

	if err := f.writeLoadCommands(buf, f.Loads); err != nil {
		return fmt.Errorf("failed to write load commands: %v", err)
	}

	endOfLoadsOffset := uint64(buf.Len())

	// Write out segment data to buffer
	for _, seg := range f.Segments() {
		if seg.Filesz > 0 {
			switch seg.Name {
			case "__TEXT":
				dat := make([]byte, seg.Filesz)
				if _, err := f.cr.ReadAtAddr(dat, seg.Addr); err != nil {
					return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
				}
				if _, err := buf.Write(dat[endOfLoadsOffset:]); err != nil {
					return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
				}
			case "__LINKEDIT":
				if f.ledata != nil && f.ledata.Len() > 0 && f.CodeSignature() != nil {
					if _, err := buf.Write(f.ledata.Bytes()); err != nil {
						return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
					}
				} else {
					dat := make([]byte, seg.Filesz)
					if _, err := f.cr.ReadAtAddr(dat, seg.Addr); err != nil {
						return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
					}
					if _, err := buf.Write(dat); err != nil {
						return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
					}
				}
			default:
				dat := make([]byte, seg.Filesz)
				if _, err := f.cr.ReadAtAddr(dat, seg.Addr); err != nil {
					return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
				}
				if _, err := buf.Write(dat); err != nil {
					return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
				}
			}
		}
	}

	return nil
}

func (f *File) optimizeLoadCommands(segMap exportSegMap, inCache bool) ([]Load, error) {
	newLoads := make([]Load, 0)
	for _, l := range f.Loads {
		switch l.Command() {
		case types.LC_SEGMENT:
			fallthrough
		case types.LC_SEGMENT_64:
			seg := l.(*Segment)
			segInfo, ok := segMap.Lookup(seg.Name)
			if !ok {
				continue
			}

			newSeg := seg.Copy()
			newLoads = append(newLoads, newSeg)
			newSeg.Offset = segInfo.New.Start
			newSeg.Filesz = segInfo.New.End - segInfo.New.Start
			newSeg.Addr = segInfo.New.VirtStart
			newSeg.Memsz = segInfo.New.VirtEnd - segInfo.New.VirtStart

			for _, sect := range seg.sections {
				newSect := sect.Copy()
				newSeg.sections = append(newSeg.sections, newSect)

				// Sections move with their own segment. Remapping them by address
				// alone is ambiguous when a cache segment starts where another
				// one ends (e.g. __LASTDATA_CONST right after __DATA_CONST).
				if newSect.Offset != 0 {
					if uint64(sect.Offset) >= segInfo.Old.Start && uint64(sect.Offset) <= segInfo.Old.End {
						newSect.Offset = uint32(segInfo.New.Start + (uint64(sect.Offset) - segInfo.Old.Start))
					} else {
						newOff, err := segMap.RemapOffset(uint64(sect.Offset))
						if err != nil {
							return nil, fmt.Errorf("Failed to remap offset: %w", err)
						}
						newSect.Offset = uint32(newOff)
					}
				}
				if sect.Addr >= segInfo.Old.VirtStart && sect.Addr <= segInfo.Old.VirtEnd {
					newSect.Addr = segInfo.New.VirtStart + (sect.Addr - segInfo.Old.VirtStart)
				} else {
					newAddr, err := segMap.RemapAddress(uint64(sect.Addr))
					if err != nil {
						return nil, fmt.Errorf("Failed to remap address: %w", err)
					}
					newSect.Addr = newAddr
				}
				// A cache image can reserve a zero-sized section without a file
				// offset and populate it while being linked (notably
				// __auth_stubs). If recovery grew such a file-backed section,
				// derive its offset from its new segment-relative address.
				if newSect.Offset == 0 && newSect.Size != 0 &&
					!newSect.Flags.IsZerofill() && !newSect.Flags.IsGbZerofill() &&
					!newSect.Flags.IsThreadLocalZerofill() {
					newSect.Offset = uint32(newSeg.Offset + (newSect.Addr - newSeg.Addr))
				}
			}
		case types.LC_SYMTAB:
			newLoad := Symtab{SymtabCmd: l.(*Symtab).SymtabCmd}
			newLoads = append(newLoads, &newLoad)

			symoff, err := segMap.RemapLinkeditOffset(uint64(newLoad.Symoff))
			if err != nil {
				return nil, fmt.Errorf("failed to remap symbol offset in %s: %v", l.Command(), err)
			}
			stroff, err := segMap.RemapLinkeditOffset(uint64(newLoad.Stroff))
			if err != nil {
				return nil, fmt.Errorf("failed to remap string offset in %s: %v", l.Command(), err)
			}

			newLoad.Symoff = uint32(symoff)
			newLoad.Stroff = uint32(stroff)
		case types.LC_DYSYMTAB:
			newLoad := Dysymtab{DysymtabCmd: l.(*Dysymtab).DysymtabCmd}
			newLoads = append(newLoads, &newLoad)

			if newLoad.Tocoffset > 0 {
				tocoffset, err := segMap.RemapLinkeditOffset(uint64(newLoad.Tocoffset))
				if err != nil {
					return nil, fmt.Errorf("failed to remap Tocoffset in %s: %v", l.Command(), err)
				}
				newLoad.Tocoffset = uint32(tocoffset)
			}
			if newLoad.Modtaboff > 0 {
				modtaboff, err := segMap.RemapLinkeditOffset(uint64(newLoad.Modtaboff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap Modtaboff in %s: %v", l.Command(), err)
				}
				newLoad.Modtaboff = uint32(modtaboff)
			}
			if newLoad.Extrefsymoff > 0 {
				extrefsymoff, err := segMap.RemapLinkeditOffset(uint64(newLoad.Extrefsymoff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap Extrefsymoff in %s: %v", l.Command(), err)
				}
				newLoad.Extrefsymoff = uint32(extrefsymoff)
			}
			if newLoad.Indirectsymoff > 0 {
				indirectsymoff, err := segMap.RemapLinkeditOffset(uint64(newLoad.Indirectsymoff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap Indirectsymoff in %s: %v", l.Command(), err)
				}
				newLoad.Indirectsymoff = uint32(indirectsymoff)
			}
			if newLoad.Extreloff > 0 {
				extreloff, err := segMap.RemapLinkeditOffset(uint64(newLoad.Extreloff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap Extreloff in %s: %v", l.Command(), err)
				}
				newLoad.Extreloff = uint32(extreloff)
			}
			if newLoad.Locreloff > 0 {
				locreloff, err := segMap.RemapLinkeditOffset(uint64(newLoad.Locreloff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap Locreloff in %s: %v", l.Command(), err)
				}
				newLoad.Locreloff = uint32(locreloff)
			}
		case types.LC_CODE_SIGNATURE:
			newLoad := CodeSignature{CodeSignatureCmd: l.(*CodeSignature).CodeSignatureCmd}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_SEGMENT_SPLIT_INFO:
			// <rdar://problem/23212513> dylibs iOS 9 dyld caches have bogus LC_SEGMENT_SPLIT_INFO
			// off, err := segMap.Remap(uint64(l.(*SplitInfo).Offset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			// }
			// l.(*SplitInfo).Offset = uint32(off)
		case types.LC_ENCRYPTION_INFO:
			newLoad := EncryptionInfo{EncryptionInfoCmd: l.(*EncryptionInfo).EncryptionInfoCmd}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_DYLD_INFO:
			newLoad := DyldInfo{DyldInfoCmd: l.(*DyldInfo).DyldInfoCmd}
			newLoads = append(newLoads, &newLoad)

			if newLoad.RebaseOff > 0 {
				rebaseOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.RebaseOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap RebaseOff in %s: %v", l.Command(), err)
				}
				newLoad.RebaseOff = uint32(rebaseOff)
			}
			if newLoad.BindOff > 0 {
				bindOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.BindOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap BindOff in %s: %v", l.Command(), err)
				}
				newLoad.BindOff = uint32(bindOff)
			}
			if newLoad.WeakBindOff > 0 {
				weakBindOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.WeakBindOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap WeakBindOff in %s: %v", l.Command(), err)
				}
				newLoad.WeakBindOff = uint32(weakBindOff)
			}
			if newLoad.LazyBindOff > 0 {
				lazyBindOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.LazyBindOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap LazyBindOff in %s: %v", l.Command(), err)
				}
				newLoad.LazyBindOff = uint32(lazyBindOff)
			}
			if newLoad.ExportOff > 0 {
				exportOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.ExportOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap ExportOff in %s: %v", l.Command(), err)
				}
				newLoad.ExportOff = uint32(exportOff)
			}
		case types.LC_DYLD_INFO_ONLY:
			newLoad := DyldInfoOnly{DyldInfo: DyldInfo{DyldInfoCmd: l.(*DyldInfoOnly).DyldInfoCmd}}
			newLoads = append(newLoads, &newLoad)

			if newLoad.RebaseOff > 0 {
				rebaseOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.RebaseOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap RebaseOff in %s: %v", l.Command(), err)
				}
				newLoad.RebaseOff = uint32(rebaseOff)
			}
			if newLoad.BindOff > 0 {
				bindOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.BindOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap BindOff in %s: %v", l.Command(), err)
				}
				newLoad.BindOff = uint32(bindOff)
			}
			if newLoad.WeakBindOff > 0 {
				weakBindOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.WeakBindOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap WeakBindOff in %s: %v", l.Command(), err)
				}
				newLoad.WeakBindOff = uint32(weakBindOff)
			}
			if newLoad.LazyBindOff > 0 {
				lazyBindOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.LazyBindOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap LazyBindOff in %s: %v", l.Command(), err)
				}
				newLoad.LazyBindOff = uint32(lazyBindOff)
			}
			if newLoad.ExportOff > 0 {
				exportOff, err := segMap.RemapLinkeditOffset(uint64(newLoad.ExportOff))
				if err != nil {
					return nil, fmt.Errorf("failed to remap ExportOff in %s: %v", l.Command(), err)
				}
				newLoad.ExportOff = uint32(exportOff)
			}
		case types.LC_FUNCTION_STARTS:
			newLoad := FunctionStarts{LinkEditData: LinkEditData{LinkEditDataCmd: l.(*FunctionStarts).LinkEditDataCmd}}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_MAIN:
			// EntryOffset is relative to __TEXT segment start, not an absolute
			// file offset, so it does not need remapping.
		case types.LC_DATA_IN_CODE:
			newLoad := DataInCode{DataInCodeCmd: l.(*DataInCode).DataInCodeCmd}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_FUNCTION_VARIANTS:
			newLoad := FunctionVariants{LinkEditData: LinkEditData{LinkEditDataCmd: l.(*FunctionVariants).LinkEditDataCmd}}
			newLoads = append(newLoads, &newLoad)

			if !inCache {
				off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
				if err != nil {
					return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				newLoad.Offset = uint32(off)
			}
		case types.LC_FUNCTION_VARIANT_FIXUPS:
			newLoad := FunctionVariantFixups{LinkEditData: LinkEditData{LinkEditDataCmd: l.(*FunctionVariantFixups).LinkEditDataCmd}}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_LAZY_LOAD_DYLIB_INFO:
			newLoad := LazyLoadDylibInfo{LinkEditData: LinkEditData{LinkEditDataCmd: l.(*LazyLoadDylibInfo).LinkEditDataCmd}}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_DYLIB_CODE_SIGN_DRS:
			newLoad := DylibCodeSignDrs{LinkEditData: LinkEditData{LinkEditDataCmd: l.(*DylibCodeSignDrs).LinkEditDataCmd}}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_ENCRYPTION_INFO_64:
			newLoad := EncryptionInfo64{EncryptionInfo64Cmd: l.(*EncryptionInfo64).EncryptionInfo64Cmd}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_LINKER_OPTIMIZATION_HINT:
			newLoad := LinkerOptimizationHint{LinkEditData: LinkEditData{LinkEditDataCmd: l.(*LinkerOptimizationHint).LinkEditDataCmd}}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)
		case types.LC_DYLD_EXPORTS_TRIE:
			newLoad := DyldExportsTrie{LinkEditData: LinkEditData{LinkEditDataCmd: l.(*DyldExportsTrie).LinkEditDataCmd}}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.Offset = uint32(off)

		case types.LC_DYLD_CHAINED_FIXUPS:
			newLoad := DyldChainedFixups{LinkEditData: LinkEditData{LinkEditDataCmd: l.(*DyldChainedFixups).LinkEditDataCmd}}
			newLoads = append(newLoads, &newLoad)

			if !inCache {
				off, err := segMap.RemapLinkeditOffset(uint64(newLoad.Offset))
				if err != nil {
					return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				newLoad.Offset = uint32(off)
			}
		case types.LC_FILESET_ENTRY:
			newLoad := FilesetEntry{
				FilesetEntryCmd: l.(*FilesetEntry).FilesetEntryCmd,
				EntryID:         l.(*FilesetEntry).EntryID,
			}
			newLoads = append(newLoads, &newLoad)

			off, err := segMap.RemapOffset(newLoad.FileOffset)
			if err != nil {
				return nil, fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			newLoad.FileOffset = off
		case types.LC_UUID:
			newLoad := UUID{UUIDCmd: l.(*UUID).UUIDCmd}
			newLoads = append(newLoads, &newLoad)
		case types.LC_BUILD_VERSION:
			newLoad := BuildVersion{
				BuildVersionCmd: l.(*BuildVersion).BuildVersionCmd,
				Tools:           make([]types.BuildVersionTool, 0),
			}
			for _, tool := range l.(*BuildVersion).Tools {
				newLoad.Tools = append(newLoad.Tools, tool)
			}
			newLoads = append(newLoads, &newLoad)
		case types.LC_SOURCE_VERSION:
			newLoad := SourceVersion{SourceVersionCmd: l.(*SourceVersion).SourceVersionCmd}
			newLoads = append(newLoads, &newLoad)
		case types.LC_UNIXTHREAD:
			newLoad := UnixThread{Thread: Thread{
				ThreadCmd: l.(*UnixThread).ThreadCmd,
				Threads:   make([]types.ThreadState, 0),
			}}
			for _, thread := range l.(*UnixThread).Threads {
				newData := make([]byte, len(thread.Data))
				copy(newData, thread.Data)

				switch thread.Flavor {
				case types.ThreadFlavor(types.ARM_THREAD_STATE64):
					var regs RegsARM64
					if err := binary.Read(bytes.NewReader(thread.Data), f.ByteOrder, &regs); err != nil {
						return nil, err
					}
					if regs.OnlyEntry() {
						// An entry point outside the image (a collection builder
						// invalidates the kernel's) is kept as it is.
						if newPC, err := segMap.RemapAddress(regs.PC); err == nil {
							regs.PC = newPC
						}
					}
					var buf bytes.Buffer
					if err := binary.Write(&buf, f.ByteOrder, &regs); err != nil {
						return nil, err
					}
					newData = buf.Bytes()
				default:
					return nil, fmt.Errorf("Unexpected Thread Flavour")
				}

				newThread := types.ThreadState{
					Flavor: thread.Flavor,
					Count:  thread.Count,
					Data:   newData,
				}
				newLoad.Threads = append(newLoad.Threads, newThread)
			}
			newLoads = append(newLoads, &newLoad)
		default:
			// Commands without file offsets (dylib, rpath, ...) are kept as is.
			newLoads = append(newLoads, l)
		}
	}
	return newLoads, nil
}

type stub struct {
	ADRP uint64
	LDR  uint64
	BR   uint64
}

type authStub struct {
	ADRP uint32
	ADD  uint32
	LDR  uint32
	BRAA uint32
}

func (f *File) resizeAuthStubs(segMap exportSegMap) {
	authGOTSection := f.Section("__DATA_CONST", "__auth_got")
	if authGOTSection == nil {
		return
	}

	authStubsSection := f.Section("__TEXT_EXEC", "__auth_stubs")
	if authStubsSection == nil {
		// Usually, the auth stubs section exists with a size of zero.
		return
	}

	// We resize the section to fit all auth stubs in it.
	stubSize := 4 * sizeOfInt32
	authStubsSize := (authGOTSection.Size / f.pointerSize()) * uint64(stubSize)
	authStubsSection.Size = authStubsSize

	textExecSegmentInfoIndex := slices.IndexFunc(segMap, func(info segMapInfo) bool { return info.Name == "__TEXT_EXEC" })
	if textExecSegmentInfoIndex < 0 {
		return
	}
	textExecSegmentInfo := segMap[textExecSegmentInfoIndex]

	requiredFileSize := textExecSegmentInfo.OrigFilesz + authStubsSize
	requiredMemSize := max(textExecSegmentInfo.OrigMemsz, requiredFileSize)
	textExecSegmentInfo.New.End = textExecSegmentInfo.New.Start + pageAlign(requiredFileSize, f.pageSize())
	textExecSegmentInfo.New.VirtEnd = textExecSegmentInfo.New.VirtStart + pageAlign(requiredMemSize, f.pageSize())
	segMap[textExecSegmentInfoIndex] = textExecSegmentInfo
	segMap.RefreshLayout()
}

func (f *File) writeAuthStubs(exportData []byte) error {
	authGOTSection := f.Section("__DATA_CONST", "__auth_got")
	if authGOTSection == nil {
		return nil
	}
	authStubsSection := f.Section("__TEXT_EXEC", "__auth_stubs")
	if authStubsSection == nil {
		return nil
	}
	if authGOTSection.Size == 0 || authStubsSection.Size == 0 {
		return nil
	}

	writeAuthStub := func(sourceAddr, targetAddress uint64) ([]byte, error) {
		pageMask := ^uint64(0xFFF)
		srcPage := sourceAddr & pageMask
		dstPage := targetAddress & pageMask

		deltaPages := int64(dstPage>>12) - int64(srcPage>>12)

		immlo := uint32(deltaPages&0x3) << 29
		immhi := uint32((deltaPages>>2)&0x7ffff) << 5
		addOffset := targetAddress & 0xFFF

		stub := authStub{
			ADRP: 0x90000011 | immlo | immhi,
			ADD:  0x91000231 | uint32(addOffset<<10),
			LDR:  0xF9400230,
			BRAA: 0xD71F0A11,
		}
		var buf bytes.Buffer
		buf.Grow(4 * sizeOfInt32)
		if err := binary.Write(&buf, binary.LittleEndian, stub); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	// Section offsets in a fileset image refer to its cache layout.  After
	// exporting, derive the destination from the exported VM map instead of
	// using that stale offset (which can otherwise overwrite the Mach-O header).
	writeOffset, err := f.GetOffset(authStubsSection.Addr)
	if err != nil {
		return fmt.Errorf("failed to locate auth stubs in exported file: %w", err)
	}
	stubsAddr := authStubsSection.Addr
	for gotAddr := authGOTSection.Addr; gotAddr < authGOTSection.Addr+authGOTSection.Size; gotAddr += f.pointerSize() {
		stub, err := writeAuthStub(stubsAddr, gotAddr)
		if err != nil {
			return err
		}

		if writeOffset+uint64(len(stub)) > uint64(len(exportData)) {
			return fmt.Errorf("auth stub at %#x exceeds exported file size", stubsAddr)
		}
		copy(exportData[writeOffset:], stub)
		writeOffset += uint64(len(stub))
		stubsAddr += uint64(len(stub))
	}

	return nil
}

// orderLoadsLikeLinker places the generated load commands where ld64 emits
// them: LC_DYLD_CHAINED_FIXUPS right after the segments and
// LC_SEGMENT_SPLIT_INFO right before LC_FUNCTION_STARTS. The order of the
// other commands is kept. kmutil copies the kernel's load commands in order,
// so this matters for reproducing a kernel collection.
func orderLoadsLikeLinker(loads []Load) []Load {
	var chained, split Load
	rest := make([]Load, 0, len(loads))
	for _, load := range loads {
		switch load.Command() {
		case types.LC_DYLD_CHAINED_FIXUPS:
			chained = load
		case types.LC_SEGMENT_SPLIT_INFO:
			split = load
		default:
			rest = append(rest, load)
		}
	}
	ordered := make([]Load, 0, len(loads))
	lastSegment := -1
	for i, load := range rest {
		if load.Command() == types.LC_SEGMENT_64 || load.Command() == types.LC_SEGMENT {
			lastSegment = i
		}
	}
	for i, load := range rest {
		if split != nil && load.Command() == types.LC_FUNCTION_STARTS {
			ordered = append(ordered, split)
			split = nil
		}
		ordered = append(ordered, load)
		if chained != nil && i == lastSegment {
			ordered = append(ordered, chained)
			chained = nil
		}
	}
	if chained != nil {
		ordered = append(ordered, chained)
	}
	if split != nil {
		ordered = append(ordered, split)
	}
	return ordered
}

func addSplitSegmentInfoLoad(fileHeader *types.FileHeader, loads []Load) []Load {
	splitInfo := &SplitInfo{
		Version: types.DYLD_CACHE_ADJ_V2_FORMAT,
		SegmentSplitInfoCmd: types.SegmentSplitInfoCmd{
			LoadCmd: types.LC_SEGMENT_SPLIT_INFO,
			Len:     uint32(binary.Size(types.SegmentSplitInfoCmd{})),
			Offset:  0,
			Size:    0,
		},
	}

	for i, load := range loads {
		if load.Command().String() == splitInfo.Command().String() {
			loads = append(loads[:i], loads[i+1:]...)
			fileHeader.NCommands--
			fileHeader.SizeCommands -= splitInfo.LoadSize()
			break
		}
	}

	loads = append(loads, splitInfo)
	fileHeader.NCommands++
	fileHeader.SizeCommands += splitInfo.LoadSize()
	return loads
}

func removeLoad(fileHeader *types.FileHeader, loads []Load, cmd types.LoadCmd) []Load {
	for i, load := range loads {
		if load.Command() == cmd {
			fileHeader.NCommands--
			fileHeader.SizeCommands -= load.LoadSize()
			return append(loads[:i], loads[i+1:]...)
		}
	}
	return loads
}

func addDyldChainedFixupsLoad(fileHeader *types.FileHeader, loads []Load) []Load {
	fixups := &DyldChainedFixups{LinkEditData: LinkEditData{
		LinkEditDataCmd: types.LinkEditDataCmd{
			LoadCmd: types.LC_DYLD_CHAINED_FIXUPS,
			Len:     uint32(binary.Size(types.LinkEditDataCmd{})),
		},
	}}

	for i, load := range loads {
		if load.Command() == fixups.Command() {
			loads = append(loads[:i], loads[i+1:]...)
			fileHeader.NCommands--
			fileHeader.SizeCommands -= fixups.LoadSize()
			break
		}
	}

	loads = append(loads, fixups)
	fileHeader.NCommands++
	fileHeader.SizeCommands += fixups.LoadSize()
	return loads
}

type chainedFixupAuth struct {
	diversity uint16
	addrDiv   uint64
	key       uint64
}

// indirectPointerSymbol returns the symbol named by an indirect pointer slot.
// This is stronger evidence than a target-address lookup when several symbols
// were folded to the same address while building the kernelcache.
func (f *File) indirectPointerSymbol(address uint64) (Symbol, bool) {
	if f.Symtab == nil || f.Dysymtab == nil {
		return Symbol{}, false
	}
	section := f.FindSectionForVMAddr(address)
	if section == nil || (!section.Flags.IsNonLazySymbolPointers() && !section.Flags.IsLazySymbolPointers()) {
		return Symbol{}, false
	}
	entry := section.Reserved1 + uint32((address-section.Addr)/f.pointerSize())
	if entry >= uint32(len(f.Dysymtab.IndirectSyms)) {
		return Symbol{}, false
	}
	symbolIndex := f.Dysymtab.IndirectSyms[entry]
	if symbolIndex&types.INDIRECT_SYMBOL_LOCAL != 0 || symbolIndex >= uint32(len(f.Symtab.Syms)) {
		return Symbol{}, false
	}
	return f.Symtab.Syms[symbolIndex], true
}

// adjustReferences rewrites cache-relative references for a standalone image.
// symbols contains the resolved imports.
func (f *File) adjustReferences(segMap exportSegMap, exportData []byte, symbols []Symbol, references []*types.SplitInfoEntry) (map[uint64]Symbol, map[uint64]uint64, map[uint64]uint64, map[uint64]chainedFixupAuth, error) {
	bindReferences := make(map[uint64]Symbol)
	rebaseReferences := make(map[uint64]uint64)
	handledReferences := make(map[uint64]uint64)
	authReferences := make(map[uint64]chainedFixupAuth)
	externalBranches := make(map[uint64]Symbol)
	adrpTargets := make(map[uint64]*types.SplitInfoEntry)
	resolvedTargets := make(map[uint64]struct{}, len(symbols))
	for _, symbol := range symbols {
		resolvedTargets[symbol.Value] = struct{}{}
	}
	// Pointer imports retain their undefined symbol names in indirect symbol
	// sections even after the collection resolves their targets. Learn that
	// target-to-name relation before processing branches. This recovers branch
	// names when a name-keyed kernel symbol map was shadowed by another image's
	// definition. Keep only unique identities: aliases such as memcpy/memmove
	// can intentionally share one implementation address.
	pointerTargetSymbols := make(map[uint64]Symbol)
	ambiguousPointerTargets := make(map[uint64]struct{})
	for _, ref := range references {
		if ref.Kind != types.DYLD_CACHE_ADJ_V2_POINTER_64 {
			continue
		}
		newSource, err := segMap.RemapAddress(ref.SourceVmAddr)
		if err != nil {
			continue
		}
		if symbol, ok := f.indirectPointerSymbol(newSource); ok {
			recordUniqueTargetSymbol(pointerTargetSymbols, ambiguousPointerTargets, ref.TargetVmAddr, symbol)
		}
	}
	for _, ref := range references {
		if ref.Kind != types.DYLD_CACHE_ADJ_V2_ARM64_OFF12 || ref.ExtraVmAddr == 0 {
			continue
		}
		current, ok := adrpTargets[ref.ExtraVmAddr]
		if !ok || ref.SourceVmAddr < current.SourceVmAddr {
			adrpTargets[ref.ExtraVmAddr] = ref
		}
	}
	for _, ref := range references {
		newSourceVmAddr, err := segMap.RemapAddress(ref.SourceVmAddr)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if ref.Kind == types.DYLD_CACHE_ADJ_V2_POINTER_64 {
			sourceOffset, err := f.GetOffset(newSourceVmAddr)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			raw := binary.LittleEndian.Uint64(exportData[sourceOffset:])
			if fixupchains.DcpArm64eIsAuth(raw) {
				auth := fixupchains.DyldChainedPtrArm64eAuthRebase{Pointer: raw}
				authReferences[newSourceVmAddr] = chainedFixupAuth{
					diversity: uint16(auth.Diversity()),
					addrDiv:   auth.AddrDiv(),
					key:       auth.Key(),
				}
			}
		}

		targetVmAddr := ref.TargetVmAddr
		if ref.Kind == types.DYLD_CACHE_ADJ_V2_ARM64_ADRP {
			if exact, ok := adrpTargets[ref.SourceVmAddr]; ok {
				targetVmAddr = exact.TargetVmAddr
			}
		}
		newTargetVmAddr, targetErr := segMap.RemapAddress(targetVmAddr)
		if targetErr != nil && ref.Kind == types.DYLD_CACHE_ADJ_V2_ARM64_ADRP {
			// ADRP encodes a page address. A cache image can start a segment in
			// the middle of that page, leaving the ADRP target just before the
			// segment's VM range. Map that overlapping page to the corresponding
			// page in the recovered image.
			pageStart := targetVmAddr &^ uint64(0xfff)
			pageEnd := pageStart + 0xfff
			for _, info := range segMap {
				if pageStart > info.Old.VirtEnd || pageEnd < info.Old.VirtStart {
					continue
				}
				newTargetVmAddr = info.New.VirtStart &^ uint64(0xfff)
				targetErr = nil
				break
			}
		}
		if targetErr == nil {
			// A weak definition can resolve back into the same image while the
			// collection is built. The standalone image must still call it through
			// its weak-coalescing stub so a later collection build can choose the
			// prevailing definition again.
			if ref.Kind == types.DYLD_CACHE_ADJ_V2_ARM64_BR26 {
				if sym, ok := pointerTargetSymbols[targetVmAddr]; ok && sym.Desc.IsWeakDefintion() {
					externalBranches[newSourceVmAddr] = sym
					continue
				}
			}
			preserveOff12 := false
			if ref.Kind == types.DYLD_CACHE_ADJ_V2_ARM64_OFF12 && ref.ExtraVmAddr != 0 {
				if adrpTarget, ok := adrpTargets[ref.ExtraVmAddr]; ok {
					if mappedADRP, err := segMap.RemapAddress(adrpTarget.TargetVmAddr); err == nil {
						// All consumers of one ADRP addressed the same 4KB page in
						// the standalone image. Kernel collection packing can move
						// coalesced storage within a segment without leaving enough
						// information to linearly remap every individual OFF12 target.
						// If this target maps to a different page than the page chosen
						// for its ADRP, retain the encoded offset. Rewriting it would
						// make the pair internally inconsistent and change behavior.
						preserveOff12 = mappedADRP&^uint64(0xfff) != newTargetVmAddr&^uint64(0xfff)
					}
				}
			}
			sourceOffset, err := f.GetOffset(newSourceVmAddr)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			targetOffset, err := f.GetOffset(newTargetVmAddr)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			switch ref.Kind {
			case types.DYLD_CACHE_ADJ_V2_POINTER_64:
				// A reference to a weak definition remains a dynamic weak-lookup
				// bind even when the cache resolved it back into this image. Keep
				// the indirect symbol so standalone loading can coalesce it again.
				if sym, ok := f.indirectPointerSymbol(newSourceVmAddr); ok && sym.Desc.IsWeakDefintion() {
					bindReferences[newSourceVmAddr] = sym
				} else {
					rebaseReferences[newSourceVmAddr] = newTargetVmAddr
				}
			case types.DYLD_CACHE_ADJ_V2_DELTA_32:
				handledReferences[newSourceVmAddr] = newTargetVmAddr
				// Adjust like the collection builder: by how far the target
				// moved relative to the source. The anchor of a delta is not
				// always the delta itself (e.g. an eh_frame CIE pointer counts
				// backwards, __copyio_vectors entries are relative to the table).
				adjust := (int64(newTargetVmAddr) - int64(targetVmAddr)) - (int64(newSourceVmAddr) - int64(ref.SourceVmAddr))
				value := int32(binary.LittleEndian.Uint32(exportData[sourceOffset:]))
				binary.LittleEndian.PutUint32(exportData[sourceOffset:], uint32(int64(value)+adjust))
			case types.DYLD_CACHE_ADJ_V2_DELTA_64:
				handledReferences[newSourceVmAddr] = newTargetVmAddr
				adjust := (int64(newTargetVmAddr) - int64(targetVmAddr)) - (int64(newSourceVmAddr) - int64(ref.SourceVmAddr))
				value := int64(binary.LittleEndian.Uint64(exportData[sourceOffset:]))
				binary.LittleEndian.PutUint64(exportData[sourceOffset:], uint64(value+adjust))
			case types.DYLD_CACHE_ADJ_V2_IMAGE_OFF_32:
				handledReferences[newSourceVmAddr] = newTargetVmAddr
				// Offset of the target from the mach_header.
				binary.LittleEndian.PutUint32(exportData[sourceOffset:], uint32(newTargetVmAddr-f.GetBaseAddress()))
			case types.DYLD_CACHE_ADJ_V2_ARM64_BR26:
				handledReferences[newSourceVmAddr] = newTargetVmAddr

				instruction := binary.LittleEndian.Uint32(exportData[sourceOffset:])
				var delta int64 = int64(targetOffset - sourceOffset)
				instruction = (instruction & 0xFC000000) | uint32((delta>>2)&0x03FFFFFF)

				var buf bytes.Buffer
				if err := binary.Write(&buf, binary.LittleEndian, instruction); err != nil {
					return nil, nil, nil, nil, err
				}
				copy(exportData[sourceOffset:], buf.Bytes())
			case types.DYLD_CACHE_ADJ_V2_ARM64_ADRP:
				handledReferences[newSourceVmAddr] = newTargetVmAddr

				pageMask := ^uint64(0xFFF)
				srcPage := newSourceVmAddr & pageMask
				dstPage := newTargetVmAddr & pageMask

				deltaPages := int64(dstPage>>12) - int64(srcPage>>12)
				immlo := uint32(deltaPages&0x3) << 29
				immhi := uint32((deltaPages>>2)&0x7ffff) << 5
				// Keep the opcode and destination register from the original
				// instruction. Only ADRP's immediate fields encode the target.
				adrpInstruction := binary.LittleEndian.Uint32(exportData[sourceOffset:])
				adrpInstruction = (adrpInstruction &^ 0x60FFFFE0) | immlo | immhi
				var buf bytes.Buffer
				if err := binary.Write(&buf, binary.LittleEndian, adrpInstruction); err != nil {
					return nil, nil, nil, nil, err
				}
				copy(exportData[sourceOffset:], buf.Bytes())
			case types.DYLD_CACHE_ADJ_V2_ARM64_OFF12:
				handledReferences[newSourceVmAddr] = newTargetVmAddr
				if preserveOff12 {
					continue
				}

				var instruction uint32 = binary.LittleEndian.Uint32(exportData[sourceOffset:])
				newPageOffset := newTargetVmAddr & 0xFFF
				newInstruction := instruction

				if (instruction & 0x3B000000) == 0x39000000 {
					// LDR/STR imm12
					var newAddend uint32
					switch instruction & 0xC0000000 {
					case 0x00000000:
						if (instruction & 0x04800000) == 0x04800000 {
							newAddend = uint32(newPageOffset) / 16
						} else {
							newAddend = uint32(newPageOffset)
						}
					case 0x40000000:
						newAddend = uint32(newPageOffset) / 2
					case 0x80000000:
						newAddend = uint32(newPageOffset) / 4
					case 0xC0000000:
						newAddend = uint32(newPageOffset) / 8
					}
					newInstruction = (instruction & 0xFFC003FF) | (newAddend << 10)
				} else if (instruction & 0xFFC00000) == 0x91000000 {
					// ADD imm12
					newInstruction = (instruction & 0xFFC003FF) | (uint32(newPageOffset) << 10)
				}

				var buf bytes.Buffer
				if err := binary.Write(&buf, binary.LittleEndian, newInstruction); err != nil {
					return nil, nil, nil, nil, err
				}
				copy(exportData[sourceOffset:], buf.Bytes())
			default:
				return nil, nil, nil, nil, fmt.Errorf("SplitInfoType not implemented")
			}
		} else {
			// External Reference
			sym, found := f.indirectPointerSymbol(newSourceVmAddr)
			if !found {
				symIndex := slices.IndexFunc(symbols, func(sym Symbol) bool { return sym.Value == targetVmAddr })
				if symIndex >= 0 {
					sym = symbols[symIndex]
					found = true
				}
			}
			if !found {
				if _, ambiguous := ambiguousPointerTargets[targetVmAddr]; !ambiguous {
					sym, found = pointerTargetSymbols[targetVmAddr]
				}
			}
			if !found {
				// Some kernelcache targets have no exported symbol.  They cannot
				// be represented as a chained bind (which requires an import
				// name), but leaving the recovered bytes intact is preferable to
				// rejecting the whole KEXT export.
				handledReferences[newSourceVmAddr] = targetVmAddr
				continue
			}

			// Chained fixups encode pointer-sized data references only.
			// Other split-info kinds address instructions or smaller values,
			// so adding them to the ARM64e pointer chain would overwrite
			// adjacent data (and can place a chain entry on a 4-byte offset).
			if ref.Kind == types.DYLD_CACHE_ADJ_V2_POINTER_64 {
				bindReferences[newSourceVmAddr] = sym
			} else if ref.Kind == types.DYLD_CACHE_ADJ_V2_ARM64_BR26 {
				externalBranches[newSourceVmAddr] = sym
			} else {
				handledReferences[newSourceVmAddr] = targetVmAddr
			}
		}
	}

	// The cache resolves cross-image calls directly. Standalone KEXTs route
	// them through generated auth stubs, whose matching GOT slots are binds.
	// Reconnect each external BL/B to that slot's stub after all pointer binds
	// have been collected (reference order is not stable).
	authGOT := f.Section("__DATA_CONST", "__auth_got")
	authStubs := f.Section("__TEXT_EXEC", "__auth_stubs")
	if authGOT != nil && authStubs != nil {
		// Several slots can bind the same name (aliases share a synthesized
		// name in stripped images); use the lowest one so output is stable.
		slotForName := make(map[string]uint64)
		for gotAddr, gotSym := range bindReferences {
			if gotAddr < authGOT.Addr || gotAddr >= authGOT.Addr+authGOT.Size {
				continue
			}
			if current, ok := slotForName[gotSym.Name]; !ok || gotAddr < current {
				slotForName[gotSym.Name] = gotAddr
			}
		}
		for branchAddr, branchSym := range externalBranches {
			gotAddr, ok := slotForName[branchSym.Name]
			if !ok {
				continue
			}
			stubAddr := authStubs.Addr + ((gotAddr-authGOT.Addr)/f.pointerSize())*16
			sourceOffset, err := f.GetOffset(branchAddr)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			instruction := binary.LittleEndian.Uint32(exportData[sourceOffset:])
			delta := int64(stubAddr) - int64(branchAddr)
			instruction = (instruction & 0xFC000000) | uint32((delta>>2)&0x03FFFFFF)
			binary.LittleEndian.PutUint32(exportData[sourceOffset:], instruction)
			handledReferences[branchAddr] = stubAddr
		}
	}
	return bindReferences, rebaseReferences, handledReferences, authReferences, nil
}

func recordUniqueTargetSymbol(symbols map[uint64]Symbol, ambiguous map[uint64]struct{}, target uint64, symbol Symbol) {
	if _, alreadyAmbiguous := ambiguous[target]; alreadyAmbiguous {
		return
	}
	if existing, ok := symbols[target]; ok && existing.Name != symbol.Name {
		delete(symbols, target)
		ambiguous[target] = struct{}{}
		return
	}
	symbols[target] = symbol
}

func (f *File) optimizeObjC(segMap exportSegMap) error {

	// classes, err := f.GetObjCClasses()
	// if err != nil {
	// 	if errors.Is(err, ErrObjcSectionNotFound) {
	// 		return nil
	// 	}
	// 	return err
	// }

	// for _, class := range classes {
	// 	if _, err := f.GetOffset(class.ClassPtr); err != nil {
	// 		fmt.Println(class)
	// 	} else {
	// 		fmt.Println("WRITE TO LINKEDIT")
	// 	}
	// }

	return nil // TODO: impliment this
}

func (f *File) optimizeLinkedit(exportData []byte, segMap exportSegMap, locals []Symbol, references []*types.SplitInfoEntry, binds map[uint64]Symbol, rebases, others map[uint64]uint64, auths map[uint64]chainedFixupAuth, functionStarts []uint64, pack bool) ([]byte, error) {
	linkedit := f.Segment("__LINKEDIT")
	if linkedit == nil {
		return nil, fmt.Errorf("unable to find __LINKEDIT segment")
	}

	var lebuf bytes.Buffer
	storeLinkeditStructure := func(structure []byte, loadCmd types.LoadCmd) error {
		if len(structure) == 0 {
			return nil
		}

		if _, err := lebuf.Write(structure); err != nil {
			return fmt.Errorf("failed to write %s data: %v", loadCmd.String(), err)
		}
		if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return fmt.Errorf("failed to write %s padding: %v", loadCmd.String(), err)
			}
		}
		return nil
	}
	storeLinkeditLoad := func(load Load) error {
		if load == nil {
			return nil
		}

		// Update Load Command. We require the load Len not to change!
		offset := uint32(types.FileHeaderSize32)
		if f.Magic == types.Magic64 {
			offset = types.FileHeaderSize64
		}
		for i := uint32(0); i < f.NCommands; i++ {
			// Each load command begins with uint32 command and length.
			cmd := types.LoadCmd(f.ByteOrder.Uint32(exportData[offset:]))
			sz := f.ByteOrder.Uint32(exportData[offset+4:])
			if cmd != load.Command() {
				offset += sz
				continue
			}
			if cmd == types.LC_SEGMENT_64 {
				if sz < 56 {
					return fmt.Errorf("invalid LC_SEGMENT_64 size %d", sz)
				}
				// Keep the command's existing section records intact. Only the
				// segment header changes after rebuilding __LINKEDIT.
				segment := load.(*Segment)
				name := string(bytes.TrimRight(exportData[offset+8:offset+24], "\x00"))
				if name != segment.Name {
					offset += sz
					continue
				}
				f.ByteOrder.PutUint64(exportData[offset+24:], segment.Addr)
				f.ByteOrder.PutUint64(exportData[offset+32:], segment.Memsz)
				f.ByteOrder.PutUint64(exportData[offset+40:], segment.Offset)
				f.ByteOrder.PutUint64(exportData[offset+48:], segment.Filesz)
				offset += sz
				continue
			}

			var buf bytes.Buffer
			load.Write(&buf, f.ByteOrder)
			loadData := buf.Bytes()

			if sz != uint32(len(loadData)) {
				return fmt.Errorf("Load size has changed: %s", load.Command().String())
			}
			copy(exportData[offset:], loadData)
			offset += sz
		}

		return nil
	}
	storeOptionalLinkeditStructure := func(data []byte, load Load) error {
		if load == nil {
			return nil
		}
		if err := storeLinkeditStructure(data, load.Command()); err != nil {
			return err
		}
		return storeLinkeditLoad(load)
	}

	if pack {
		buf, load, pages, importOrdinal, err := f.createChainedFixups(uint32(linkedit.Offset)+uint32(lebuf.Len()), segMap, binds, rebases, others, auths)
		if err != nil {
			return nil, err
		}
		if err := storeOptionalLinkeditStructure(buf, load); err != nil {
			return nil, err
		}
		exportData, err = f.overwriteFixupEntries(exportData, pages, importOrdinal)
		if err != nil {
			return nil, err
		}
	}

	buf, load, exports, err := f.createExportsTree(uint32(linkedit.Offset) + uint32(lebuf.Len()))
	if err != nil {
		return nil, err
	}
	if err := storeOptionalLinkeditStructure(buf, load); err != nil {
		return nil, err
	}

	buf, load, err = f.createDataInCode(uint32(linkedit.Offset) + uint32(lebuf.Len()))
	if err != nil {
		return nil, err
	}
	if err := storeOptionalLinkeditStructure(buf, load); err != nil {
		return nil, err
	}

	if pack {
		splitRefs, err := f.finalSplitInfoReferences(exportData, segMap, references, binds, rebases, others, auths)
		if err != nil {
			return nil, err
		}
		buf, load, err = f.createSegmentSplitInfo(uint32(linkedit.Offset)+uint32(lebuf.Len()), splitRefs)
		if err != nil {
			return nil, err
		}
		if err := storeOptionalLinkeditStructure(buf, load); err != nil {
			return nil, err
		}
	}

	// TODO: LC_DYLIB_CODE_SIGN_DRS
	// createCodeSignDrs()
	// storeLinkeditStructure(buf, load)

	// TODO: LC_LINKER_OPTIMIZATION_HINT
	// createLinkerOptimizationHints()
	// storeLinkeditStructure(buf, load)

	buf, load, err = f.createFunctionStarts(uint32(linkedit.Offset)+uint32(lebuf.Len()), functionStarts)
	if err != nil {
		return nil, err
	}
	if err := storeOptionalLinkeditStructure(buf, load); err != nil {
		return nil, err
	}

	buf, load, err = f.createFunctionVariants(uint32(linkedit.Offset) + uint32(lebuf.Len()))
	if err != nil {
		return nil, err
	}
	if err := storeOptionalLinkeditStructure(buf, load); err != nil {
		return nil, err
	}

	buf, load, err = f.createFunctionVariantFixups(uint32(linkedit.Offset) + uint32(lebuf.Len()))
	if err != nil {
		return nil, err
	}
	if err := storeOptionalLinkeditStructure(buf, load); err != nil {
		return nil, err
	}

	buf, load, err = f.createDyldInfo(uint32(linkedit.Offset) + uint32(lebuf.Len()))
	if err != nil {
		return nil, err
	}
	if err := storeOptionalLinkeditStructure(buf, load); err != nil {
		return nil, err
	}

	// TODO: LC_CODE_SIGNATURE
	// createCodeSignature()
	// storeLinkeditStructure(buf, load)

	symtabOffset := uint32(linkedit.Offset) + uint32(lebuf.Len())
	nLocalSyms, nExtdefSyms, nUndefSyms, symtabBuf, stringPoolBuf, symIndexMap, err := f.createSymtabWithIndexMap(symtabOffset, segMap, locals, exports)
	if err != nil {
		return nil, err
	}
	if err := storeLinkeditStructure(symtabBuf, types.LC_SYMTAB); err != nil {
		return nil, err
	}

	indirectSymtabOffset := uint32(linkedit.Offset) + uint32(lebuf.Len())
	indirectSymtabBuf, err := f.createIndirectSymtab(symIndexMap, f.indirectSymbolFromBinds(symtabBuf, stringPoolBuf, binds))
	if err != nil {
		return nil, err
	}
	if err := storeLinkeditStructure(indirectSymtabBuf, types.LC_DYSYMTAB); err != nil {
		return nil, err
	}

	stringPoolOffset := uint32(linkedit.Offset) + uint32(lebuf.Len())
	if err := storeLinkeditStructure(stringPoolBuf, types.LC_SYMTAB); err != nil {
		return nil, err
	}

	symtabLoad, dysymtabLoad := f.createSymtabLoads(symtabOffset, indirectSymtabOffset, stringPoolOffset, uint32(len(stringPoolBuf)), nLocalSyms, nExtdefSyms, nUndefSyms)
	if err := storeLinkeditLoad(symtabLoad); err != nil {
		return nil, err
	}
	if err := storeLinkeditLoad(dysymtabLoad); err != nil {
		return nil, err
	}

	linkedit.Filesz = uint64(lebuf.Len())
	linkedit.Memsz = pageAlign(linkedit.Filesz, f.pageSize())
	if err := storeLinkeditLoad(linkedit); err != nil {
		return nil, err
	}

	leData := lebuf.Bytes()
	copied := copy(exportData[linkedit.Offset:], leData)
	if copied < len(leData) {
		exportData = append(exportData, leData[copied:]...)
	}
	// createExportFile copied the original cache-backed __LINKEDIT before it
	// was rebuilt.  Do not retain that obsolete tail after the new segment.
	endOfLinkedit := uint64(linkedit.Offset) + linkedit.Filesz
	if uint64(len(exportData)) > endOfLinkedit {
		exportData = exportData[:endOfLinkedit]
	}

	return exportData, nil
}

func (f *File) createChainedFixups(offset uint32, segMap exportSegMap, binds map[uint64]Symbol, rebases, others map[uint64]uint64, auths map[uint64]chainedFixupAuth) ([]byte, Load, map[[2]int][]fixupchains.Fixup, map[string]uint32, error) {
	fixups := f.sortFixups(binds, rebases, auths)

	// Undefined symbols marked N_WEAK_REF may be missing when the collection
	// is linked; their imports must keep the weak-import bit.
	weakRefs := make(map[string]bool)
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			if sym.Type.IsUndefinedSym() && sym.Desc.IsWeakReferenced() {
				weakRefs[sym.Name] = true
			}
		}
	}
	imports, importOrdinal := assignOrdinals(f.orderFixupsForImports(fixups, segMap), binds, weakRefs)
	format, strings, importBytes, err := createStringPool(imports)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to create string pool: %w", err)
	}

	pages, err := f.groupFixupsByPage(fixups)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to group fixups: %w", err)
	}

	starts, err := f.createStartsInSegmentStructure(pages)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	data := createChainedFixupsStructure(starts, importBytes, len(imports), strings, format)

	fixupsLoad := &DyldChainedFixups{LinkEditData{
		LinkEditDataCmd: types.LinkEditDataCmd{
			LoadCmd: types.LC_DYLD_CHAINED_FIXUPS,
			Len:     uint32(binary.Size(types.LinkEditDataCmd{})),
			Offset:  offset,
			Size:    uint32(len(data)),
		},
	}}
	return data, fixupsLoad, pages, importOrdinal, nil
}

func (f *File) sortFixups(binds map[uint64]Symbol, rebases map[uint64]uint64, auths map[uint64]chainedFixupAuth) []fixupchains.Fixup {
	fixups := make([]fixupchains.Fixup, 0)
	for addr, sym := range binds {
		if auth, ok := auths[addr]; ok {
			fixups = append(fixups, fixupchains.NewDyldChainedPtrArm64eAuthBind(addr, 0, auth.diversity, auth.addrDiv, auth.key, 0, sym.Name))
		} else {
			bind, err := fixupchains.NewDyldChainedPtrArm64eBind(addr, 0, 0, 0, sym.Name)
			if err == nil {
				fixups = append(fixups, bind)
			}
		}
	}
	// DYLD_CHAINED_PTR_ARM64E_KERNEL rebase targets are offsets from the
	// mach_header, not VM addresses. KEXTs are exported at address zero, where
	// both coincide, but the kernel keeps its link address.
	base := f.GetBaseAddress()
	for addr, target := range rebases {
		target -= base
		if auth, ok := auths[addr]; ok {
			fixups = append(fixups, fixupchains.NewDyldChainedPtrArm64eAuthRebase(addr, target, auth.diversity, auth.addrDiv, auth.key, 0))
		} else {
			fixups = append(fixups, fixupchains.DyldChainedPtrArm64eRebase{Fixup: addr, Pointer: target})
		}
	}
	sort.Slice(fixups, func(i, j int) bool {
		return fixups[i].Offset() < fixups[j].Offset()
	})
	return fixups
}

// orderFixupsForImports reproduces ld's import insertion order. Indirect
// pointer sections are visited from low to high addresses. In regular sections,
// atoms are visited from low to high addresses while their relocations are
// linked in reverse address order.
func (f *File) orderFixupsForImports(fixups []fixupchains.Fixup, segMap exportSegMap) []fixupchains.Fixup {
	atomStarts := make(map[*types.Section][]uint64)
	vtableStarts := make(map[*types.Section][]uint64)
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			if !sym.Type.IsDefinedInSection() || sym.Value == 0 {
				continue
			}
			address, err := segMap.RemapAddress(sym.Value)
			if err != nil {
				continue
			}
			if section := f.FindSectionForVMAddr(address); section != nil {
				atomStarts[section] = append(atomStarts[section], address)
				if strings.HasPrefix(sym.Name, "__ZTV") {
					vtableStarts[section] = append(vtableStarts[section], address)
				}
			}
		}
	}
	for section, starts := range vtableStarts {
		sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
		vtableStarts[section] = slices.Compact(starts)
	}
	// ld emits copied external C++ vtables as anonymous atoms, so their starts
	// are not represented by local symbols. The first two entries are the D1
	// and D0 destructors, authenticated with the stable 0x3771 and 0x56b7
	// discriminators. Recover those boundaries so imports in adjacent external
	// vtables are not all reversed as if they belonged to one large atom.
	for index := 0; index+1 < len(fixups); index++ {
		first, firstOK := fixups[index].(fixupchains.DyldChainedPtrArm64eAuthRebase)
		second, secondOK := fixups[index+1].(fixupchains.DyldChainedPtrArm64eAuthRebase)
		if !firstOK || !secondOK || first.Offset()+8 != second.Offset() ||
			first.Diversity() != 0x3771 || second.Diversity() != 0x56b7 {
			continue
		}
		section := f.FindSectionForVMAddr(first.Offset())
		if section != nil && section == f.FindSectionForVMAddr(second.Offset()) {
			atomStarts[section] = append(atomStarts[section], first.Offset())
		}
	}
	// A linker-created data atom can immediately follow a named vtable without
	// retaining its own symbol. A gap followed by an unauthenticated bind marks
	// that boundary; otherwise its imports would be reversed together with the
	// preceding vtable's relocation list.
	for index := 0; index+1 < len(fixups); index++ {
		current, next := fixups[index], fixups[index+1]
		if next.Offset() <= current.Offset()+8 {
			continue
		}
		if _, ok := current.(fixupchains.DyldChainedPtrArm64eAuthBind); !ok {
			continue
		}
		if _, ok := next.(fixupchains.DyldChainedPtrArm64eBind); !ok {
			continue
		}
		section := f.FindSectionForVMAddr(current.Offset())
		if section == nil || section != f.FindSectionForVMAddr(next.Offset()) {
			continue
		}
		starts := vtableStarts[section]
		preceding := sort.Search(len(starts), func(i int) bool { return starts[i] > current.Offset() })
		if preceding == 0 || (preceding < len(starts) && starts[preceding] <= next.Offset()) {
			continue
		}
		atomStarts[section] = append(atomStarts[section], next.Offset())
	}
	for section, starts := range atomStarts {
		sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
		atomStarts[section] = slices.Compact(starts)
	}

	type fixupOrder struct {
		fixup       fixupchains.Fixup
		section     *types.Section
		sectionAddr uint64
		atomAddr    uint64
		indirect    bool
	}
	ordered := make([]fixupOrder, 0, len(fixups))
	for _, fixup := range fixups {
		entry := fixupOrder{fixup: fixup}
		entry.section = f.FindSectionForVMAddr(fixup.Offset())
		if entry.section != nil {
			entry.sectionAddr = entry.section.Addr
			entry.atomAddr = entry.section.Addr
			entry.indirect = entry.section.Flags.IsNonLazySymbolPointers() || entry.section.Flags.IsLazySymbolPointers()
			starts := atomStarts[entry.section]
			if index := sort.Search(len(starts), func(i int) bool { return starts[i] > fixup.Offset() }); index > 0 {
				entry.atomAddr = starts[index-1]
			}
		}
		ordered = append(ordered, entry)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.sectionAddr != right.sectionAddr {
			return left.sectionAddr < right.sectionAddr
		}
		if left.indirect != right.indirect {
			return left.indirect
		}
		if left.indirect {
			return left.fixup.Offset() < right.fixup.Offset()
		}
		if left.atomAddr != right.atomAddr {
			return left.atomAddr < right.atomAddr
		}
		return left.fixup.Offset() > right.fixup.Offset()
	})

	result := make([]fixupchains.Fixup, len(ordered))
	for index, entry := range ordered {
		result[index] = entry.fixup
	}
	return result
}

func assignOrdinals(fixups []fixupchains.Fixup, binds map[uint64]Symbol, weakRefs map[string]bool) ([]fixupchains.DcfImport, map[string]uint32) {
	weakDefinitions := make(map[string]bool)
	for _, symbol := range binds {
		if symbol.Desc.IsWeakDefintion() {
			weakDefinitions[symbol.Name] = true
		}
	}
	imports := make([]fixupchains.DcfImport, 0)
	importOrdinal := make(map[string]uint32)
	for _, fixup := range fixups {
		var name string
		switch fixup := fixup.(type) {
		case fixupchains.DyldChainedPtrArm64eBind:
			name = fixup.Name()
		case fixupchains.DyldChainedPtrArm64eAuthBind:
			name = fixup.Name()
		default:
			continue
		}
		if _, ok := importOrdinal[name]; ok {
			continue
		}
		importOrdinal[name] = uint32(len(imports))
		// KEXT imports are resolved in the flat namespace.
		var dcImport fixupchains.DyldChainedImport = 0xfe
		if weakDefinitions[name] {
			dcImport = 0xfd // BIND_SPECIAL_DYLIB_WEAK_LOOKUP
		}
		if weakRefs[name] {
			dcImport |= 1 << 8 // weak_import
		}

		imports = append(imports, fixupchains.DcfImport{
			Name:   name,
			Import: dcImport,
		})
	}
	return imports, importOrdinal
}

func createStringPool(imports []fixupchains.DcfImport) (fixupchains.ImportFormat, []byte, []byte, error) {
	var strings []byte
	strings = append(strings, 0)
	nameOffset := make([]uint32, len(imports))

	useAddends := false
	for i, imp := range imports {
		nameOffset[i] = uint32(len(strings))

		strings = append(strings, []byte(imp.Name)...)
		strings = append(strings, 0)

		if imp.Addend() != 0 {
			useAddends = true
		}
	}

	// Imports are 4 bytes each for format 1, 8 bytes each for format 2.
	importEntrySize := 4
	format := fixupchains.DC_IMPORT
	if useAddends {
		importEntrySize = 8
		format = fixupchains.DC_IMPORT_ADDEND
	}

	importBytes := make([]byte, importEntrySize*len(imports))
	for i, imp := range imports {
		if imp.LibOrdinal() < -15 || imp.LibOrdinal() > 240 {
			return 0, nil, nil, fmt.Errorf(
				"library ordinal %d cannot be represented by import format",
				imp.LibOrdinal(),
			)
		}

		// bits:
		//
		//  0..7   lib ordinal
		//     8    weak import
		//  9..31  name offset
		//
		v := uint32(uint8(int8(imp.LibOrdinal())))
		if imp.WeakImport() {
			v |= 1 << 8
		}

		if nameOffset[i] >= 1<<23 {
			return 0, nil, nil, fmt.Errorf("symbol string pool exceeds 23-bit offset")
		}

		v |= nameOffset[i] << 9

		binary.LittleEndian.PutUint32(importBytes[i*importEntrySize:], v)

		if useAddends {
			binary.LittleEndian.PutUint32(
				importBytes[i*importEntrySize+4:],
				uint32(imp.Addend()),
			)
		}
	}
	return format, strings, importBytes, nil
}

func (f *File) groupFixupsByPage(fixups []fixupchains.Fixup) (map[[2]int][]fixupchains.Fixup, error) {
	pages := make(map[[2]int][]fixupchains.Fixup)
	segments := f.Segments()
	for _, fixup := range fixups {
		seg := -1

		for i, s := range segments {
			if s.Addr <= fixup.Offset() && fixup.Offset() < s.Addr+s.Memsz {
				seg = i
				break
			}
		}

		if seg < 0 {
			return nil, fmt.Errorf("fixup at %#x does not belong to a segment", fixup.Offset())
		}

		page := uint32((fixup.Offset() - segments[seg].Addr) / chainedFixupsPageSize)

		key := [2]int{seg, int(page)}
		pages[key] = append(pages[key], fixup)
	}
	return pages, nil
}

func (f *File) createStartsInSegmentStructure(pages map[[2]int][]fixupchains.Fixup) ([]byte, error) {
	segments := f.Segments()
	segCount := len(segments)
	// dyld_chained_starts_in_image:
	//   uint32 seg_count
	//   uint32 seg_info_offset[seg_count]
	const startsImageHeaderSize = 4
	startsSize := startsImageHeaderSize + 4*segCount

	starts := make([]byte, startsSize)
	binary.LittleEndian.PutUint32(starts[0:4], uint32(segCount))

	segmentInfoOffsets := make([]uint32, segCount)
	for segIndex, seg := range segments {
		maxPage := -1
		for key := range pages {
			if key[0] != segIndex {
				continue
			}
			if key[1] > maxPage {
				maxPage = key[1]
			}
		}

		if maxPage < 0 {
			// No fixups in this segment.
			continue
		}

		var overflowStarts []uint16
		pageStarts := make([]uint16, maxPage+1)
		for page := 0; page <= maxPage; page++ {
			fs := pages[[2]int{segIndex, page}]

			if len(fs) == 0 {
				pageStarts[page] = uint16(fixupchains.DYLD_CHAINED_PTR_START_NONE)
				continue
			}

			// A chain can cover adjacent fixups whose delta fits in the
			// ARM64e pointer's 11-bit next field.  Only the first fixup in
			// each such chain belongs in page_start/chain_starts.
			chainStarts, err := chainedFixupStarts(fs)
			if err != nil {
				return nil, err
			}

			// Convert every chain start into an offset within this page.
			offsets := make([]uint16, 0, len(chainStarts))

			for _, fixup := range chainStarts {
				absoluteOffset := fixup.Offset() - seg.Addr

				// page is already part of the key, but use the
				// actual page-relative offset here rather than
				// simply taking absoluteOffset % pageSize.
				pageOffset := absoluteOffset - uint64(page)*chainedFixupsPageSize

				if pageOffset >= chainedFixupsPageSize {
					return nil, fmt.Errorf(
						"fixup offset %#x is not in segment page %d (page size %#x)",
						absoluteOffset,
						page,
						chainedFixupsPageSize,
					)
				}

				// 0xffff is reserved for START_NONE and
				// 0x8000 is reserved for START_MULTI.
				if pageOffset >= 0x8000 {
					return nil, fmt.Errorf(
						"fixup offset %#x cannot be represented in page_start",
						pageOffset,
					)
				}

				offsets = append(offsets, uint16(pageOffset))
			}

			// They should normally already be ordered, but make
			// the encoding deterministic and satisfy dyld's
			// requirement that multiple starts are ascending.
			sort.Slice(offsets, func(i, j int) bool {
				return offsets[i] < offsets[j]
			})

			if len(offsets) == 1 {
				pageStarts[page] = offsets[0]
				continue
			}

			// Multiple starts on this page.
			//
			// The value in page_start[] is an index into the
			// overflow array with bit 15 set.
			index := len(overflowStarts)

			if index >= 0x8000 {
				return nil, fmt.Errorf("too many chained-fixups overflow starts")
			}

			pageStarts[page] =
				uint16(fixupchains.DYLD_CHAINED_PTR_START_MULTI) |
					uint16(index)

			for i, offset := range offsets {
				if i == len(offsets)-1 {
					offset |= uint16(
						fixupchains.DYLD_CHAINED_PTR_START_LAST,
					)
				}

				overflowStarts = append(overflowStarts, offset)
			}
		}

		// dyld_chained_starts_in_segment:
		//
		// uint32 size
		// uint16 page_size
		// uint16 pointer_format
		// uint64 segment_offset
		// uint32 max_valid_pointer
		// uint16 page_count
		// uint16 page_start[page_count]
		//
		const startsInSegmentHeaderSize = 22
		segmentInfoSize := startsInSegmentHeaderSize + 2*len(pageStarts) + 2*len(overflowStarts)

		// 8-byte alignment between segment records.
		for len(starts)%8 != 0 {
			starts = append(starts, 0)
		}

		segmentInfoOffset := uint32(len(starts))
		segmentInfoOffsets[segIndex] = segmentInfoOffset

		record := make([]byte, segmentInfoSize)

		binary.LittleEndian.PutUint32(record[0:4], uint32(segmentInfoSize))
		binary.LittleEndian.PutUint16(record[4:6], uint16(chainedFixupsPageSize))
		const ptrFormat = uint16(fixupchains.DYLD_CHAINED_PTR_ARM64E_KERNEL)
		binary.LittleEndian.PutUint16(record[6:8], ptrFormat)
		binary.LittleEndian.PutUint64(record[8:16], seg.Addr-f.GetBaseAddress())
		binary.LittleEndian.PutUint32(record[16:20], 0)
		binary.LittleEndian.PutUint16(record[20:22], uint16(len(pageStarts)))

		for page, start := range pageStarts {
			offset := startsInSegmentHeaderSize + 2*page
			binary.LittleEndian.PutUint16(record[offset:offset+2], start)
		}

		// chain_starts[] / overflow starts
		overflowOffset := startsInSegmentHeaderSize + 2*len(pageStarts)
		for i, start := range overflowStarts {
			binary.LittleEndian.PutUint16(record[overflowOffset+2*i:overflowOffset+2*i+2], start)
		}

		starts = append(starts, record...)
	}

	// Fill seg_info_offset[].
	for i, off := range segmentInfoOffsets {
		binary.LittleEndian.PutUint32(
			starts[4+4*i:8+4*i],
			off,
		)
	}
	return starts, nil
}

func align4(v int) int {
	return (v + 3) &^ 3
}

func align8(v int) int {
	return (v + 7) &^ 7
}

func createChainedFixupsStructure(starts []byte, importBytes []byte, importsCount int, strings []byte, format fixupchains.ImportFormat) []byte {
	fixupsHeaderSize := binary.Size(fixupchains.DyldChainedFixupsHeader{})
	startsOffset := align8(fixupsHeaderSize)
	importsOffset := align4(startsOffset + len(starts))
	symbolsOffset := importsOffset + len(importBytes)
	total := align8(symbolsOffset + len(strings)) // ld64 pads the blob itself
	header := fixupchains.DyldChainedFixupsHeader{
		FixupsVersion: 0,
		StartsOffset:  uint32(startsOffset),
		ImportsOffset: uint32(importsOffset),
		SymbolsOffset: uint32(symbolsOffset),
		ImportsCount:  uint32(importsCount),
		ImportsFormat: format,
		SymbolsFormat: fixupchains.DC_SFORMAT_UNCOMPRESSED,
	}

	out := make([]byte, total)
	copy(out, header.Data())
	copy(out[startsOffset:], starts)
	copy(out[importsOffset:], importBytes)
	copy(out[symbolsOffset:], strings)
	return out
}

func (f *File) overwriteFixupEntries(exportData []byte, pages map[[2]int][]fixupchains.Fixup, importOrdinal map[string]uint32) ([]byte, error) {
	for _, fs := range pages {
		for i := range fs {
			var next uint64
			if i+1 < len(fs) {
				delta := fs[i+1].Offset() - fs[i].Offset()
				// Standalone KEXTs use ARM64E_KERNEL, whose next field is an
				// 11-bit count of 4-byte units.
				if delta%arm64eKernelStride == 0 {
					next = delta / arm64eKernelStride
				}
				if delta%arm64eKernelStride != 0 || next > arm64eMaxNext {
					// This starts a new chain on the same page.  Its offset is
					// recorded in chain_starts by createStartsInSegmentStructure.
					next = 0
				}
			}

			var value uint64
			if imp, ok := fs[i].(fixupchains.DyldChainedPtrArm64eBind); ok {
				ordinal, ok := importOrdinal[imp.Name()]
				if !ok {
					return nil, fmt.Errorf(
						"missing import ordinal for %s",
						imp.Name(),
					)
				}

				bind, err := fixupchains.NewDyldChainedPtrArm64eBind(imp.Fixup, uint16(ordinal), imp.SignExtendedAddend(), next, imp.Name())
				if err != nil {
					return nil, err
				}
				value = bind.Pointer
			} else if imp, ok := fs[i].(fixupchains.DyldChainedPtrArm64eAuthBind); ok {
				ordinal, ok := importOrdinal[imp.Name()]
				if !ok {
					return nil, fmt.Errorf("missing import ordinal for %s", imp.Name())
				}
				bind := fixupchains.NewDyldChainedPtrArm64eAuthBind(imp.Fixup, uint16(ordinal), uint16(imp.Diversity()), imp.AddrDiv(), imp.Key(), next, imp.Name())
				value = bind.Pointer
			} else if imp, ok := fs[i].(fixupchains.DyldChainedPtrArm64eAuthRebase); ok {
				rebase := fixupchains.NewDyldChainedPtrArm64eAuthRebase(imp.Fixup, imp.Target(), uint16(imp.Diversity()), imp.AddrDiv(), imp.Key(), next)
				value = rebase.Pointer
			} else if imp, ok := fs[i].(fixupchains.DyldChainedPtrArm64eRebase); ok {
				rebase := fixupchains.NewDyldChainedPtrArm64eRebase(imp.Fixup, imp.Pointer, next)
				value = rebase.Pointer
			}

			offset, err := f.GetOffset(fs[i].Offset())
			if err != nil {
				return nil, err
			}

			binary.LittleEndian.PutUint64(exportData[offset:offset+8], value)
		}
	}
	return exportData, nil
}

const (
	chainedFixupsPageSize = uint64(0x1000)
	arm64eKernelStride    = uint64(4)
	arm64eMaxNext         = uint64(0x7ff)
)

// chainedFixupStarts returns the fixups that need an entry in page_start or
// chain_starts. A gap too large for an ARM64e next field terminates one chain
// and begins the next; it is not an error.
func chainedFixupStarts(fixups []fixupchains.Fixup) ([]fixupchains.Fixup, error) {
	if len(fixups) == 0 {
		return nil, nil
	}

	starts := make([]fixupchains.Fixup, 0, 1)
	starts = append(starts, fixups[0])
	for i := 1; i < len(fixups); i++ {
		delta := fixups[i].Offset() - fixups[i-1].Offset()
		if delta%arm64eKernelStride != 0 || delta/arm64eKernelStride > arm64eMaxNext {
			starts = append(starts, fixups[i])
		}
	}
	return starts, nil
}

// optimize LC_DYLD_EXPORTS_TRIE
func (f *File) createExportsTree(offset uint32) ([]byte, Load, []trie.TrieExport, error) {
	if dexpTrie := f.DyldExportsTrie(); dexpTrie != nil {
		exports, err := f.DyldExports()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get LC_DYLD_EXPORTS_TRIE exports: %v", err)
		}
		dat := make([]byte, dexpTrie.Size)
		if _, err = f.cr.ReadAt(dat, int64(dexpTrie.Offset)); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read LC_DYLD_EXPORTS_TRIE data: %v", err)
		}

		dexpTrie.Offset = offset
		dexpTrie.Size = uint32(len(dat))
		return dat, dexpTrie, exports, nil
	}
	return nil, nil, nil, nil
}

// optimize LC_DATA_IN_CODE
func (f *File) createDataInCode(offset uint32) ([]byte, Load, error) {
	if dataNCode := f.DataInCode(); dataNCode != nil {
		dat := make([]byte, dataNCode.Size)
		if _, err := f.cr.ReadAt(dat, int64(dataNCode.Offset)); err != nil {
			return nil, nil, fmt.Errorf("failed to read LC_DATA_IN_CODE data: %v", err)
		}

		dataNCode.Offset = offset
		dataNCode.Size = uint32(len(dat))
		return dat, dataNCode, nil
	}
	return nil, nil, nil
}

// Reconstruct LC_SEGMENT_SPLIT_INFO
func (f *File) createSegmentSplitInfo(offset uint32, references []*types.SplitInfoEntry) ([]byte, Load, error) {
	// The first element is the macho_header
	sections := []types.Section{{}}
	for _, l := range f.Loads {
		if s, ok := l.(*Segment); ok {
			for j := uint32(0); j < s.Nsect; j++ {
				sections = append(sections, *f.Sections[j+s.Firstsect])
			}
		}
	}

	type FromOffsetMap map[uint8][]uint64
	type ToOffsetMap map[uint64]FromOffsetMap
	type WholeMap map[uint32]ToOffsetMap
	whole := make(WholeMap)
	for _, entry := range references {
		fromSectionIndex, fromSectionOffset, ok := f.splitInfoSectionLocation(sections, entry.SourceVmAddr, false)
		if !ok {
			return nil, nil, fmt.Errorf("split-info source %#x is not in an exported section", entry.SourceVmAddr)
		}
		toSectionIndex, toSectionOffset, ok := f.splitInfoSectionLocation(sections, entry.TargetVmAddr, true)
		if !ok {
			return nil, nil, fmt.Errorf("split-info target %#x is not in the exported image", entry.TargetVmAddr)
		}

		comboIndex := fromSectionIndex<<16 | toSectionIndex
		toOffsets, ok := whole[uint32(comboIndex)]
		if !ok {
			toOffsets = make(ToOffsetMap)
		}
		fromOffsets, ok := toOffsets[toSectionOffset]
		if !ok {
			fromOffsets = make(FromOffsetMap)
		}
		offsets, ok := fromOffsets[uint8(entry.Kind)]
		if !ok {
			offsets = make([]uint64, 0)
		}
		offsets = append(offsets, fromSectionOffset)
		fromOffsets[uint8(entry.Kind)] = offsets
		toOffsets[toSectionOffset] = fromOffsets
		whole[uint32(comboIndex)] = toOffsets
	}

	var splitSegInfoBuf bytes.Buffer
	binary.Write(&splitSegInfoBuf, f.ByteOrder, uint8(types.DYLD_CACHE_ADJ_V2_FORMAT))
	trie.EncodeUleb128(&splitSegInfoBuf, uint64(len(whole)))
	// Emit in ld64's order (sorted by from/to section, to offset and kind) so
	// the output is deterministic.
	combos := make([]uint32, 0, len(whole))
	for comboIndex := range whole {
		combos = append(combos, comboIndex)
	}
	slices.Sort(combos)
	for _, comboIndex := range combos {
		toOffsets := whole[comboIndex]
		fromSectionIndex := comboIndex >> 16
		toSectionIndex := comboIndex & 0xFFFF

		trie.EncodeUleb128(&splitSegInfoBuf, uint64(fromSectionIndex))
		trie.EncodeUleb128(&splitSegInfoBuf, uint64(toSectionIndex))
		trie.EncodeUleb128(&splitSegInfoBuf, uint64(len(toOffsets)))

		keys := make([]uint64, 0)
		for k, _ := range toOffsets {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var lastToOffset uint64 = 0
		for _, toSectionOffset := range keys {
			fromOffsets := toOffsets[toSectionOffset]
			toSectionDelta := toSectionOffset - uint64(lastToOffset)

			trie.EncodeUleb128(&splitSegInfoBuf, uint64(toSectionDelta))
			trie.EncodeUleb128(&splitSegInfoBuf, uint64(len(fromOffsets)))

			kinds := make([]uint8, 0, len(fromOffsets))
			for kind := range fromOffsets {
				kinds = append(kinds, kind)
			}
			slices.Sort(kinds)
			for _, kind := range kinds {
				offsets := fromOffsets[kind]
				trie.EncodeUleb128(&splitSegInfoBuf, uint64(kind))
				trie.EncodeUleb128(&splitSegInfoBuf, uint64(len(offsets)))

				slices.Sort(offsets)
				var lastFromOffset uint64 = 0
				for _, offset := range offsets {
					fromOffsetDelta := offset - uint64(lastFromOffset)
					trie.EncodeUleb128(&splitSegInfoBuf, uint64(fromOffsetDelta))
					lastFromOffset = offset
				}
			}
			lastToOffset = toSectionOffset
		}
	}
	splitSegInfoBuf.WriteByte(0x00)
	data := padLinkeditBlob(splitSegInfoBuf.Bytes())

	load := LinkEditData{
		LinkEditDataCmd: types.LinkEditDataCmd{
			LoadCmd: types.LC_SEGMENT_SPLIT_INFO,
			Len:     uint32(binary.Size(types.LinkEditDataCmd{})),
			Offset:  offset,
			Size:    uint32(len(data)),
		},
	}

	return data, &load, nil
}

// splitInfoSectionLocation returns the split-seg section index and offset that
// address addr. Index 0 is the mach_header, which the collection builder moves
// together with the first (__TEXT) segment. Targets may point one past the end
// of a section (e.g. section end symbols), as ld64 records them.
func (f *File) splitInfoSectionLocation(sections []types.Section, addr uint64, allowEnd bool) (int, uint64, bool) {
	for i := 1; i < len(sections); i++ {
		if sections[i].Addr <= addr && addr < sections[i].Addr+sections[i].Size {
			return i, addr - sections[i].Addr, true
		}
	}
	if allowEnd {
		for i := 1; i < len(sections); i++ {
			if sections[i].Size == 0 && addr == sections[i].Addr {
				return i, 0, true
			}
		}
		for i := 1; i < len(sections); i++ {
			if sections[i].Size > 0 && addr == sections[i].Addr+sections[i].Size {
				return i, addr - sections[i].Addr, true
			}
		}
	}
	if seg := f.FindSegmentForVMAddr(addr); seg != nil && seg.Name == "__TEXT" {
		return 0, addr - seg.Addr, true
	}
	return 0, 0, false
}

// decodeOff12 returns the byte offset encoded by an ARM64 imm12 load/store or ADD.
func decodeOff12(instruction uint32) (uint64, bool) {
	if instruction&0x3B000000 == 0x39000000 {
		imm := uint64((instruction >> 10) & 0xFFF)
		switch instruction & 0xC0000000 {
		case 0x00000000:
			if instruction&0x04800000 == 0x04800000 {
				return imm * 16, true
			}
			return imm, true
		case 0x40000000:
			return imm * 2, true
		case 0x80000000:
			return imm * 4, true
		default:
			return imm * 8, true
		}
	}
	if instruction&0xFFC00000 == 0x91000000 {
		return uint64((instruction >> 10) & 0xFFF), true
	}
	return 0, false
}

// finalSplitInfoReferences describes the references of the exported image as
// ld64 would: in the exported address space and after the export rewrote them.
// Cache references are not usable as-is: external calls now go through auth
// stubs, external pointers became binds (which split-seg info never records),
// and targets outside this image cannot be adjusted by a collection builder.
func (f *File) finalSplitInfoReferences(exportData []byte, segMap exportSegMap, references []*types.SplitInfoEntry, binds map[uint64]Symbol, rebases, others map[uint64]uint64, auths map[uint64]chainedFixupAuth) ([]*types.SplitInfoEntry, error) {
	inImage := func(addr uint64) bool {
		for _, seg := range f.Segments() {
			if seg.Name != "__LINKEDIT" && seg.Addr <= addr && addr <= seg.Addr+seg.Memsz {
				return true
			}
		}
		return false
	}
	type key struct {
		source uint64
		kind   types.SplitInfoKind
	}
	seen := make(map[key]struct{})
	var out []*types.SplitInfoEntry
	add := func(kind types.SplitInfoKind, source, target uint64) {
		k := key{source, kind}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, &types.SplitInfoEntry{Kind: kind, SourceVmAddr: source, TargetVmAddr: target})
	}
	for _, ref := range references {
		source, err := segMap.RemapAddress(ref.SourceVmAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to remap split-info source %#x: %w", ref.SourceVmAddr, err)
		}
		switch ref.Kind {
		case types.DYLD_CACHE_ADJ_V2_POINTER_64, types.DYLD_CACHE_ADJ_V2_THREADED_POINTER_64:
			if _, ok := binds[source]; ok {
				continue
			}
			if target, ok := rebases[source]; ok && inImage(target) {
				// ld64 describes authenticated (arm64e) pointers as threaded
				// pointers and plain rebases as regular pointers.
				kind := types.DYLD_CACHE_ADJ_V2_POINTER_64
				if _, isAuth := auths[source]; isAuth {
					kind = types.DYLD_CACHE_ADJ_V2_THREADED_POINTER_64
				}
				add(kind, source, target)
			}
		case types.DYLD_CACHE_ADJ_V2_ARM64_OFF12:
			target, ok := others[source]
			if !ok || !inImage(target) {
				continue
			}
			// The instruction addresses the page loaded by its ADRP plus the
			// encoded page offset. The builder re-encodes it from the target's
			// page offset, so describe exactly that address.
			if off, err := f.GetOffset(source); err == nil && off+4 <= uint64(len(exportData)) {
				if encoded, ok := decodeOff12(binary.LittleEndian.Uint32(exportData[off:])); ok {
					page := target &^ uint64(0xFFF)
					if ref.ExtraVmAddr != 0 {
						if adrp, err := segMap.RemapAddress(ref.ExtraVmAddr); err == nil {
							if t, ok := others[adrp]; ok && inImage(t) {
								page = t &^ uint64(0xFFF)
							}
						}
					}
					if target = page | encoded; !inImage(target) {
						continue
					}
				}
			}
			add(ref.Kind, source, target)
		default:
			if target, ok := others[source]; ok && inImage(target) {
				add(ref.Kind, source, target)
			}
		}
	}
	// Generated auth stubs: ADRP + ADD address their __auth_got slot.
	authGOT := f.Section("__DATA_CONST", "__auth_got")
	authStubs := f.Section("__TEXT_EXEC", "__auth_stubs")
	if authGOT != nil && authStubs != nil && authGOT.Size > 0 && authStubs.Size > 0 {
		for i := uint64(0); i < authGOT.Size/f.pointerSize() && i*16+8 <= authStubs.Size; i++ {
			gotAddr := authGOT.Addr + i*f.pointerSize()
			stubAddr := authStubs.Addr + i*16
			add(types.DYLD_CACHE_ADJ_V2_ARM64_ADRP, stubAddr, gotAddr)
			add(types.DYLD_CACHE_ADJ_V2_ARM64_OFF12, stubAddr+4, gotAddr)
		}
	}
	return out, nil
}

// optimize LC_FUNCTION_STARTS
func (f *File) createFunctionStarts(offset uint32, starts []uint64) ([]byte, Load, error) {
	if fstarts := f.FunctionStarts(); fstarts != nil {
		var dat []byte
		if starts != nil {
			dat = encodeFunctionStarts(f.GetBaseAddress(), starts)
		} else {
			dat = make([]byte, fstarts.Size)
			if _, err := f.cr.ReadAt(dat, int64(fstarts.Offset)); err != nil {
				return nil, nil, fmt.Errorf("failed to read LC_FUNCTION_STARTS data: %v", err)
			}
		}

		fstarts.Offset = offset
		fstarts.Size = uint32(len(dat))
		return dat, fstarts, nil
	}
	return nil, nil, nil
}

// remappedFunctionStarts returns the LC_FUNCTION_STARTS addresses of the
// source image in the exported address space (nil without function starts).
// The encoding is relative to the image's __TEXT, whose distance to the code
// differs between a kernelcache entry and the exported image, so the raw
// table cannot be copied.
func (f *File) remappedFunctionStarts(segMap exportSegMap) ([]uint64, error) {
	fstarts := f.FunctionStarts()
	if fstarts == nil {
		return nil, nil
	}
	dat := make([]byte, fstarts.Size)
	if _, err := f.cr.ReadAt(dat, int64(fstarts.Offset)); err != nil {
		return nil, fmt.Errorf("failed to read LC_FUNCTION_STARTS data: %v", err)
	}
	r := bytes.NewReader(dat)
	addr := f.GetBaseAddress()
	starts := make([]uint64, 0)
	for r.Len() > 0 {
		delta, err := trie.ReadUleb128(r)
		if err != nil || delta == 0 {
			break
		}
		addr += delta
		newAddr, err := segMap.RemapAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to remap function start %#x: %w", addr, err)
		}
		starts = append(starts, newAddr)
	}
	slices.Sort(starts)
	return slices.Compact(starts), nil
}

// encodeFunctionStarts encodes LC_FUNCTION_STARTS as ld64 does: ULEB128 deltas
// starting at the mach_header and a terminating zero.
func encodeFunctionStarts(base uint64, starts []uint64) []byte {
	var buf bytes.Buffer
	last := base
	for _, start := range starts {
		trie.EncodeUleb128(&buf, start-last)
		last = start
	}
	buf.WriteByte(0)
	return padLinkeditBlob(buf.Bytes())
}

// padLinkeditBlob zero-pads LINKEDIT data to pointer alignment. ld64 includes
// this padding in the load command's datasize.
func padLinkeditBlob(data []byte) []byte {
	for len(data)%8 != 0 {
		data = append(data, 0)
	}
	return data
}

// optimize LC_FUNCTION_VARIANTS
func (f *File) createFunctionVariants(offset uint32) ([]byte, Load, error) {
	if fvars := f.FunctionVariants(); fvars != nil {
		dat := make([]byte, fvars.Size)
		if _, err := f.cr.ReadAt(dat, int64(fvars.Offset)); err != nil {
			return nil, nil, fmt.Errorf("failed to read LC_FUNCTION_VARIANTS data: %v", err)
		}

		fvars.Offset = offset
		fvars.Size = uint32(len(dat))
		return dat, fvars, nil
	}
	return nil, nil, nil
}

// optimize LC_FUNCTION_VARIANT_FIXUPS
func (f *File) createFunctionVariantFixups(offset uint32) ([]byte, Load, error) {
	if fvfix := f.FunctionVariantFixups(); fvfix != nil {
		dat := make([]byte, fvfix.Size)
		if _, err := f.cr.ReadAt(dat, int64(fvfix.Offset)); err != nil {
			return nil, nil, fmt.Errorf("failed to read LC_FUNCTION_VARIANT_FIXUPS data: %v", err)
		}

		fvfix.Offset = offset
		fvfix.Size = uint32(len(dat))
		return dat, fvfix, nil
	}
	return nil, nil, nil
}

// optimize LC_DYLD_INFO|LC_DYLD_INFO_ONLY
func (f *File) createDyldInfo(offset uint32) ([]byte, Load, error) {
	buf := make([]byte, 0)
	if dinfo := f.DyldInfo(); dinfo != nil {
		if dinfo.RebaseSize > 0 {
			dat := make([]byte, dinfo.RebaseSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.RebaseOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s rebase data: %v", dinfo.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dinfo.RebaseOff = offset
			offset += uint32(len(dat))
		}
		if dinfo.BindSize > 0 {
			dat := make([]byte, dinfo.BindSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.BindOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s bind data: %v", dinfo.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dinfo.BindOff = offset
			offset += uint32(len(dat))
		}
		if dinfo.WeakBindSize > 0 {
			dat := make([]byte, dinfo.WeakBindSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.WeakBindOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s weak bind data: %v", dinfo.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dinfo.WeakBindOff = offset
			offset += uint32(len(dat))
		}
		if dinfo.LazyBindSize > 0 {
			dat := make([]byte, dinfo.LazyBindSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.LazyBindOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s lazy bind data: %v", dinfo.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dinfo.LazyBindOff = offset
			offset += uint32(len(dat))
		}
		if dinfo.ExportSize > 0 {
			dat := make([]byte, dinfo.ExportSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.ExportOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s export data: %v", dinfo.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dinfo.ExportOff = offset
			offset += uint32(len(dat))
		}

		return buf, dinfo, nil
	} else if dionly := f.DyldInfoOnly(); dionly != nil {
		if dionly.RebaseSize > 0 {
			dat := make([]byte, dionly.RebaseSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.RebaseOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s rebase data: %v", dionly.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dionly.RebaseOff = offset
			offset += uint32(len(dat))
		}
		if dionly.BindSize > 0 {
			dat := make([]byte, dionly.BindSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.BindOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s bind data: %v", dionly.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dionly.BindOff = offset
			offset += uint32(len(dat))
		}
		if dionly.WeakBindSize > 0 {
			dat := make([]byte, dionly.WeakBindSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.WeakBindOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s weak bind data: %v", dionly.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dionly.WeakBindOff = offset
			offset += uint32(len(dat))
		}
		if dionly.LazyBindSize > 0 {
			dat := make([]byte, dionly.LazyBindSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.LazyBindOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s lazy bind data: %v", dionly.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dionly.LazyBindOff = offset
			offset += uint32(len(dat))
		}
		if dionly.ExportSize > 0 {
			dat := make([]byte, dionly.ExportSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.ExportOff)); err != nil {
				return nil, nil, fmt.Errorf("failed to read %s export data: %v", dionly.LoadCmd, err)
			}
			buf = append(buf, dat...)
			dionly.ExportOff = offset
			offset += uint32(len(dat))
		}

		return buf, dionly, nil
	} else {
		return nil, nil, nil
	}
}

func (f *File) createSymtab(offset uint32, segMap exportSegMap, locals []Symbol, exports []trie.TrieExport) (uint32, uint32, uint32, []byte, []byte, error) {
	nLocalSyms, nExtdefSyms, nUndefSyms, symtab, strtab, _, err := f.createSymtabWithIndexMap(offset, segMap, locals, exports)
	return nLocalSyms, nExtdefSyms, nUndefSyms, symtab, strtab, err
}

// createSymtabWithIndexMap also returns the new symbol table index of every
// entry of f.Symtab.Syms (or -1 when it was dropped) for the indirect table.
func (f *File) createSymtabWithIndexMap(offset uint32, segMap exportSegMap, locals []Symbol, exports []trie.TrieExport) (uint32, uint32, uint32, []byte, []byte, []int, error) {
	// Collect all symbols into three categories for correct DYSYMTAB ordering:
	// locals first, then external defined, then undefined.
	type symEntry struct {
		sym  Symbol
		name string
		orig int // index in f.Symtab.Syms, or -1
	}
	var localSyms, extdefSyms, undefSyms []symEntry
	remap := func(sym Symbol) (Symbol, error) {
		if !sym.Type.IsDefinedInSection() || sym.Value == 0 {
			return sym, nil
		}
		value, err := segMap.RemapAddress(sym.Value)
		if err != nil {
			return Symbol{}, fmt.Errorf("failed to remap symbol %s at %#x: %w", sym.Name, sym.Value, err)
		}
		sym.Value = value
		return sym, nil
	}

	// extra symbols (unmapped locals from DSC, or resolved imports from fileset KC)
	for _, lsym := range locals {
		var err error
		lsym, err = remap(lsym)
		if err != nil {
			return 0, 0, 0, nil, nil, nil, err
		}
		if lsym.Type.IsUndefinedSym() {
			// Extra imports carry their resolved target only for matching.
			lsym.Value = 0
		}
		e := symEntry{sym: lsym, name: lsym.Name, orig: -1}
		switch {
		case !lsym.Type.IsExternalSym():
			localSyms = append(localSyms, e)
		case lsym.Type.IsUndefinedSym():
			undefSyms = append(undefSyms, e)
		default:
			extdefSyms = append(extdefSyms, e)
		}
	}
	// original symbol table entries
	if f.Symtab != nil {
		for idx, sym := range f.Symtab.Syms {
			if sym.Name == "<redacted>" {
				continue
			}
			var err error
			sym, err = remap(sym)
			if err != nil {
				return 0, 0, 0, nil, nil, nil, err
			}
			e := symEntry{sym: sym, name: sym.Name, orig: idx}
			switch {
			case !sym.Type.IsExternalSym():
				localSyms = append(localSyms, e)
			case sym.Type.IsUndefinedSym():
				undefSyms = append(undefSyms, e)
			default:
				extdefSyms = append(extdefSyms, e)
			}
		}
	}
	// Re-exports and absolute exports from LC_DYLD_EXPORTS_TRIE (external defined).
	for _, exp := range exports {
		switch {
		case exp.Flags.ReExport():
			target := exp.ReExport
			if target == "" {
				// An empty trie import name means re-exported under the same name.
				target = exp.Name
			}
			extdefSyms = append(extdefSyms, symEntry{
				sym: Symbol{
					Name:         exp.Name,
					IndirectName: target,
					Type:         (types.N_INDR | types.N_EXT),
					Sect:         0,
					Desc:         0,
					Value:        exp.Address,
				},
				name: exp.Name,
				orig: -1,
			})
		case exp.Flags.Absolute():
			extdefSyms = append(extdefSyms, symEntry{
				sym:  Symbol{Name: exp.Name, Type: types.N_ABS | types.N_EXT, Value: exp.Address},
				name: exp.Name,
				orig: -1,
			})
		case exp.Flags.ThreadLocal():
			slog.Debug("skipping thread-local trie export; retaining any existing symtab entry", "name", exp.Name)
		}
	}

	nLocalSyms := uint32(len(localSyms))
	nExtdefSyms := uint32(len(extdefSyms))
	nUndefSyms := uint32(len(undefSyms))

	var buf bytes.Buffer
	var newSymNames bytes.Buffer

	// Lay out the string pool like Apple's tools do for binaries without
	// debug stabs: four zero bytes, then the names of the external defined,
	// undefined and local symbols (each in symbol table order), padded to the
	// pointer size.
	// Indirect symbols store their target name immediately after their own name.
	newSymNames.Write([]byte{0, 0, 0, 0})
	strx := make(map[*symEntry]uint32)
	indirectStrx := make(map[*symEntry]uint32)
	for _, group := range [][]symEntry{extdefSyms, undefSyms, localSyms} {
		for i := range group {
			e := &group[i]
			if e.name != "" {
				strx[e] = uint32(newSymNames.Len())
				newSymNames.WriteString(e.name + "\x00")
			}
			if e.sym.Type.IsIndirectSym() && e.sym.IndirectName != "" {
				indirectStrx[e] = uint32(newSymNames.Len())
				newSymNames.WriteString(e.sym.IndirectName + "\x00")
			}
		}
	}
	newSymNames.Write(make([]byte, pointerAlignPad(newSymNames.Len(), f.pointerSize())))
	// write symbols in DYSYMTAB order: locals, external defined, undefined
	writeSym := func(e *symEntry) error {
		nlist := types.Nlist{
			Name: strx[e],
			Type: e.sym.Type,
			Sect: e.sym.Sect,
			Desc: e.sym.Desc,
		}
		value := e.sym.Value
		if e.sym.Type.IsIndirectSym() {
			// N_INDR values index the rebuilt pool, not the source string table.
			value = uint64(indirectStrx[e])
		}
		// 32-bit files carry 12-byte nlist entries
		var entry any = types.Nlist64{Nlist: nlist, Value: value}
		if !f.is64bit() {
			entry = types.Nlist32{Nlist: nlist, Value: uint32(value)}
		}
		return binary.Write(&buf, binary.LittleEndian, entry)
	}
	var indexMap []int
	if f.Symtab != nil {
		indexMap = make([]int, len(f.Symtab.Syms))
		for i := range indexMap {
			indexMap[i] = -1
		}
	}
	next := 0
	for _, group := range []struct {
		kind    string
		entries []symEntry
	}{{"local", localSyms}, {"extdef", extdefSyms}, {"undef", undefSyms}} {
		for i := range group.entries {
			e := &group.entries[i]
			if err := writeSym(e); err != nil {
				return 0, 0, 0, nil, nil, nil, fmt.Errorf("failed to write %s symbol to NEW linkedit data: %v", group.kind, err)
			}
			if e.orig >= 0 {
				indexMap[e.orig] = next
			}
			next++
		}
	}

	return nLocalSyms, nExtdefSyms, nUndefSyms, buf.Bytes(), newSymNames.Bytes(), indexMap, nil
}

// createIndirectSymtab copies the indirect symbol table, renumbering entries
// to the rebuilt symbol table. Sentinel values (INDIRECT_SYMBOL_LOCAL,
// INDIRECT_SYMBOL_ABS) are kept.
func (f *File) createIndirectSymtab(indexMap []int, fallback ...func(entry int) (uint32, bool)) ([]byte, error) {
	for idx, indSym := range f.Dysymtab.IndirectSyms {
		if indSym&(types.INDIRECT_SYMBOL_LOCAL|types.INDIRECT_SYMBOL_ABS) != 0 {
			continue
		}
		if int(indSym) >= len(indexMap) || indexMap[indSym] < 0 {
			if len(fallback) > 0 && fallback[0] != nil {
				if newIndex, ok := fallback[0](idx); ok {
					f.Dysymtab.IndirectSyms[idx] = newIndex
					continue
				}
			}
			// The symbol is not part of the rebuilt table (e.g. <redacted>).
			f.Dysymtab.IndirectSyms[idx] = types.INDIRECT_SYMBOL_LOCAL
			continue
		}
		f.Dysymtab.IndirectSyms[idx] = uint32(indexMap[indSym])
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, f.Dysymtab.IndirectSyms); err != nil {
		return nil, fmt.Errorf("failed to write indirect symbol table to NEW linkedit data: %v", err)
	}
	return buf.Bytes(), nil
}

// indirectSymbolFromBinds names indirect symbol table entries whose original
// symbol is unknown (a stripped kernel collection keeps the table but not the
// symbols). A pointer slot takes the import bound there; an auth stub takes the
// import of its __auth_got slot, as written by writeAuthStubs.
func (f *File) indirectSymbolFromBinds(symtab, strtab []byte, binds map[uint64]Symbol) func(int) (uint32, bool) {
	undefined := make(map[string]uint32)
	for i := 0; i+16 <= len(symtab); i += 16 {
		strx := binary.LittleEndian.Uint32(symtab[i:])
		ntype := types.NType(symtab[i+4])
		if !ntype.IsUndefinedSym() || int(strx) >= len(strtab) {
			continue
		}
		name := strtab[strx:]
		if end := bytes.IndexByte(name, 0); end >= 0 {
			name = name[:end]
		}
		undefined[string(name)] = uint32(i / 16)
	}
	authGOT := f.Section("__DATA_CONST", "__auth_got")
	return func(entry int) (uint32, bool) {
		for _, sec := range f.Sections {
			start := uint64(sec.Reserved1)
			var slot uint64
			switch {
			case sec.Flags.IsNonLazySymbolPointers() || sec.Flags.IsLazySymbolPointers():
				count := sec.Size / f.pointerSize()
				if uint64(entry) < start || uint64(entry) >= start+count {
					continue
				}
				slot = sec.Addr + (uint64(entry)-start)*f.pointerSize()
			case sec.Name == "__auth_stubs" && authGOT != nil:
				if uint64(entry) < start || uint64(entry) >= start+sec.Size/16 {
					continue
				}
				slot = authGOT.Addr + (uint64(entry)-start)*f.pointerSize()
			default:
				continue
			}
			if sym, ok := binds[slot]; ok {
				index, ok := undefined[sym.Name]
				return index, ok
			}
			return 0, false
		}
		return 0, false
	}
}

func (f *File) createSymtabLoads(symtabOffset, indirectSymtabOffset, stringPoolOffset, stringPoolSize, nLocalSyms, nExtdefSyms, nUndefSyms uint32) (Load, Load) {
	f.Symtab.Nsyms = nLocalSyms + nExtdefSyms + nUndefSyms
	f.Symtab.Symoff = symtabOffset
	f.Symtab.Stroff = stringPoolOffset
	f.Symtab.Strsize = stringPoolSize

	// Apple convention: when LC_DATA_IN_CODE has no data, set dataoff = symoff
	if dataNCode := f.DataInCode(); dataNCode != nil && dataNCode.Size == 0 && f.Symtab != nil {
		dataNCode.Offset = f.Symtab.Symoff
	}

	f.Dysymtab.Ilocalsym = 0
	f.Dysymtab.Nlocalsym = nLocalSyms
	f.Dysymtab.Iextdefsym = nLocalSyms
	f.Dysymtab.Nextdefsym = nExtdefSyms
	f.Dysymtab.Iundefsym = nLocalSyms + nExtdefSyms
	f.Dysymtab.Nundefsym = nUndefSyms
	f.Dysymtab.Extreloff = 0
	f.Dysymtab.Nextrel = 0
	f.Dysymtab.Locreloff = 0
	f.Dysymtab.Nlocrel = 0
	f.Dysymtab.Nindirectsyms = uint32(len(f.Dysymtab.IndirectSyms))
	f.Dysymtab.Indirectsymoff = indirectSymtabOffset

	return f.Symtab, f.Dysymtab
}

func (f *File) writeLoadCommands(buf *bytes.Buffer, loads []Load) error {
	for _, l := range loads {
		switch l.Command() {
		case types.LC_SEGMENT:
			fallthrough
		case types.LC_SEGMENT_64:
			seg := l.(*Segment)
			if err := seg.Write(buf, f.ByteOrder); err != nil {
				return err
			}
			for _, sect := range seg.sections {
				if err := sect.Write(buf, f.ByteOrder); err != nil {
					return err
				}
			}
		default:
			if err := l.Write(buf, f.ByteOrder); err != nil {
				return err
			}
		}
	}
	return nil
}
