package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"

	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

type segInfo struct {
	Start uint64
	End   uint64
	// Size  uint64
}
type segMapInfo struct {
	Name string
	Old  segInfo
	New  segInfo
}

func (i segMapInfo) LessThan(o segMapInfo) bool {
	return i.Old.Start < o.Old.Start
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

func (m exportSegMap) Remap(offset uint64) (uint64, error) {
	for _, segInfo := range m {
		if segInfo.Old.Start <= offset && offset <= segInfo.Old.End {
			return segInfo.New.Start + (offset - segInfo.Old.Start), nil
		}
	}
	return 0, fmt.Errorf("failed to remapp offset %#x", offset)
}

// Export exports an in-memory or cached dylib|kext MachO to a file
func (f *File) Export(path string, dcf *fixupchains.DyldChainedFixups, baseAddress uint64, locals []Symbol) error {
	var buf bytes.Buffer
	var segMap exportSegMap

	inCache := f.FileHeader.Flags.DylibInCache()

	if inCache {
		f.FileHeader.Flags &= 0x7FFFFFFF // remove in-cache bit
	}

	if err := f.FileHeader.Write(&buf, f.ByteOrder); err != nil {
		return fmt.Errorf("failed to write file header to buffer: %v", err)
	}

	// create segment offset map
	var newSegOffset uint64
	for _, seg := range f.Segments() {
		segMap = append(segMap, segMapInfo{
			Name: seg.Name,
			Old: segInfo{
				Start: seg.Offset,
				End:   seg.Offset + seg.Filesz,
			},
			New: segInfo{
				Start: newSegOffset,
				End:   newSegOffset + seg.Filesz,
			},
		})
		newSegOffset += seg.Filesz
	}

	sort.Sort(segMap)

	if err := f.optimizeLoadCommands(segMap); err != nil {
		return fmt.Errorf("failed to optimize load commands: %v", err)
	}

	if inCache {
		f.optimizeLinkedit(locals)
	}

	if err := f.writeLoadCommands(&buf); err != nil {
		return fmt.Errorf("failed to write load commands: %v", err)
	}

	endOfLoadsOffset := uint64(buf.Len())

	// Write out segment data to buffer
	for _, seg := range f.Segments() {
		if seg.Filesz > 0 {
			dat := make([]byte, seg.Filesz)

			_, err := f.cr.ReadAtAddr(dat, seg.Addr)
			if err != nil {
				return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
			}

			if seg.Name == "__TEXT" {
				if _, err := buf.Write(dat[endOfLoadsOffset:]); err != nil {
					return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
				}
				continue
			}

			if _, err := buf.Write(dat); err != nil {
				return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
			}
			// TODO: align the data to page OR to 64bit ?
			// align := uint32(types.RoundUp(uint64(buf.Len()), 4)) - uint32(buf.Len())
			// if align > 0 {
			// 	adata := make([]byte, align)
			// 	if _, err := buf.Write(adata); err != nil {
			// 		return fmt.Errorf("failed to add aligned at the end of segment %s data: %v", seg.Name, err)
			// 	}
			// }
		}
	}

	if err := ioutil.WriteFile(path, buf.Bytes(), 0755); err != nil {
		return fmt.Errorf("failed to write exported MachO to file %s: %v", path, err)
	}

	if dcf != nil {
		newFile, err := os.OpenFile(path, os.O_WRONLY, 0755)
		if err != nil {
			return fmt.Errorf("failed to open exported MachO %s: %v", path, err)
		}
		defer newFile.Close()

		fi, err := newFile.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %v", path, err)
		}
		fileSize := fi.Size()

		for _, start := range dcf.Starts {
			if start.PageStarts != nil {
				for _, fixup := range start.Fixups {
					off, err := segMap.Remap(fixup.Offset())
					if err != nil {
						off = fixup.Offset()
						// return fmt.Errorf("failed to remap fixup at offset %#x: %v", off, err)
					}

					if off == 0 || off > uint64(fileSize) {
						continue
					}

					if _, err := newFile.Seek(int64(off), io.SeekStart); err != nil {
						return fmt.Errorf("failed to seek in exported file to offset %#x from the start: %v", off, err)
					}

					switch fx := fixup.(type) {
					case fixupchains.Bind:
						// var addend string
						// addr := uint64(f.Offset()) + m.GetBaseAddress()
						// if fullAddend := dcf.Imports[f.Ordinal()].Addend() + f.Addend(); fullAddend > 0 {
						// 	addend = fmt.Sprintf(" + %#x", fullAddend)
						// 	addr += fullAddend
						// }
						// sec = m.FindSectionForVMAddr(addr)
						// lib := m.LibraryOrdinalName(dcf.Imports[f.Ordinal()].LibOrdinal())
						// if sec != nil && sec != lastSec {
						// 	fmt.Printf("%s.%s\n", sec.Seg, sec.Name)
						// }
						// fmt.Printf("%s\t%s/%s%s\n", fixupchains.Bind(f).String(m.GetBaseAddress()), lib, f.Name(), addend)
					case fixupchains.Rebase:
						addr := uint64(fx.Target()) + baseAddress
						if err := binary.Write(newFile, f.ByteOrder, addr); err != nil {
							return fmt.Errorf("failed to write fixup address %#x: %v", addr, err)
						}
					}
				}
			}
		}
	}

	return nil
}

func (f *File) optimizeLoadCommands(segMap exportSegMap) error {
	for _, l := range f.Loads {
		switch l.Command() {
		case types.LC_SEGMENT:
			fallthrough
		case types.LC_SEGMENT_64:
			seg := l.(*Segment)

			off, err := segMap.Remap(seg.Offset)
			if err != nil {
				return fmt.Errorf("failed to remap offset in segment %s: %v", seg.Name, err)
			}
			seg.Offset = off

			for i := uint32(0); i < seg.Nsect; i++ {
				if f.Sections[i+seg.Firstsect].Offset != 0 {
					off, err := segMap.Remap(uint64(f.Sections[i+seg.Firstsect].Offset))
					if err != nil {
						return fmt.Errorf("failed to remap offset in section %s.%s: %v", seg.Name, f.Sections[i+seg.Firstsect].Name, err)
					}
					f.Sections[i+seg.Firstsect].Offset = uint32(off)
				}

				// roff, err := segMap.Remap(uint64(f.Sections[i+seg.Firstsect].Reloff))
				// if err != nil {
				// 	return fmt.Errorf("failed to remap rel offset in section %s: %v", f.Sections[i+seg.Firstsect].Name, err)
				// }
				// f.Sections[i+seg.Firstsect].Reloff = uint32(roff)
			}
		case types.LC_SYMTAB:
			stroff, err := segMap.Remap(uint64(l.(*Symtab).Stroff))
			if err != nil {
				return fmt.Errorf("failed to remap string offset in %s: %v", types.LC_SYMTAB, err)
			}
			l.(*Symtab).Stroff = uint32(stroff)

			symoff, err := segMap.Remap(uint64(l.(*Symtab).Symoff))
			if err != nil {
				return fmt.Errorf("failed to remap symbol offset in %s: %v", types.LC_SYMTAB, err)
			}
			l.(*Symtab).Symoff = uint32(symoff)
		case types.LC_DYSYMTAB:
			// tocoffset, err := segMap.Remap(uint64(l.(*Dysymtab).Tocoffset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap Tocoffset in %s: %v", types.LC_DYSYMTAB, err)
			// }
			// l.(*Dysymtab).Tocoffset = uint32(tocoffset)
			// modtaboff, err := segMap.Remap(uint64(l.(*Dysymtab).Modtaboff))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap Modtaboff in %s: %v", types.LC_DYSYMTAB, err)
			// }
			// l.(*Dysymtab).Modtaboff = uint32(modtaboff)
			// extrefsymoff, err := segMap.Remap(uint64(l.(*Dysymtab).Extrefsymoff))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap Extrefsymoff %s: %v", types.LC_DYSYMTAB, err)
			// }
			// l.(*Dysymtab).Extrefsymoff = uint32(extrefsymoff)
			indirectsymoff, err := segMap.Remap(uint64(l.(*Dysymtab).Indirectsymoff))
			if err != nil {
				return fmt.Errorf("failed to remap Indirectsymoff in %s: %v", types.LC_DYSYMTAB, err)
			}
			l.(*Dysymtab).Indirectsymoff = uint32(indirectsymoff)
			// extreloff, err := segMap.Remap(uint64(l.(*Dysymtab).Extreloff))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap Extreloff in %s: %v", types.LC_DYSYMTAB, err)
			// }
			// l.(*Dysymtab).Extreloff = uint32(extreloff)
			// locreloff, err := segMap.Remap(uint64(l.(*Dysymtab).Locreloff))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap Locreloff in %s: %v", types.LC_DYSYMTAB, err)
			// }
			// l.(*Dysymtab).Locreloff = uint32(locreloff)
		case types.LC_CODE_SIGNATURE:
			off, err := segMap.Remap(uint64(l.(*CodeSignature).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_CODE_SIGNATURE, err)
			}
			l.(*CodeSignature).Offset = uint32(off)
		case types.LC_SEGMENT_SPLIT_INFO:
			// <rdar://problem/23212513> dylibs iOS 9 dyld caches have bogus LC_SEGMENT_SPLIT_INFO
			// off, err := segMap.Remap(uint64(l.(*SplitInfo).Offset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap offset in %s: %v", types.LC_SEGMENT_SPLIT_INFO, err)
			// }
			// l.(*SplitInfo).Offset = uint32(off)
		case types.LC_ENCRYPTION_INFO:
			off, err := segMap.Remap(uint64(l.(*EncryptionInfo).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_ENCRYPTION_INFO, err)
			}
			l.(*EncryptionInfo).Offset = uint32(off)
		case types.LC_DYLD_INFO:
			if l.(*DyldInfo).RebaseOff > 0 {
				rebaseOff, err := segMap.Remap(uint64(l.(*DyldInfo).RebaseOff))
				if err != nil {
					return fmt.Errorf("failed to remap RebaseOff in %s: %v", types.LC_DYLD_INFO, err)
				}
				l.(*DyldInfoOnly).RebaseOff = uint32(rebaseOff)
			}
			if l.(*DyldInfoOnly).BindOff > 0 {
				bindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).BindOff))
				if err != nil {
					return fmt.Errorf("failed to remap BindOff in %s: %v", types.LC_DYLD_INFO, err)
				}
				l.(*DyldInfoOnly).BindOff = uint32(bindOff)
			}
			if l.(*DyldInfo).WeakBindOff > 0 {
				weakBindOff, err := segMap.Remap(uint64(l.(*DyldInfo).WeakBindOff))
				if err != nil {
					return fmt.Errorf("failed to remap WeakBindOff in %s: %v", types.LC_DYLD_INFO, err)
				}
				l.(*DyldInfo).WeakBindOff = uint32(weakBindOff)
			}
			if l.(*DyldInfo).LazyBindOff > 0 {
				lazyBindOff, err := segMap.Remap(uint64(l.(*DyldInfo).LazyBindOff))
				if err != nil {
					return fmt.Errorf("failed to remap LazyBindOff in %s: %v", types.LC_DYLD_INFO, err)
				}
				l.(*DyldInfo).LazyBindOff = uint32(lazyBindOff)
			}
			if l.(*DyldInfo).ExportOff > 0 {
				exportOff, err := segMap.Remap(uint64(l.(*DyldInfo).ExportOff))
				if err != nil {
					return fmt.Errorf("failed to remap ExportOff in %s: %v", types.LC_DYLD_INFO, err)
				}
				l.(*DyldInfo).ExportOff = uint32(exportOff)
			}
		case types.LC_DYLD_INFO_ONLY:
			if l.(*DyldInfoOnly).RebaseOff > 0 {
				rebaseOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).RebaseOff))
				if err != nil {
					return fmt.Errorf("failed to remap RebaseOff in %s: %v", types.LC_DYLD_INFO_ONLY, err)
				}
				l.(*DyldInfoOnly).RebaseOff = uint32(rebaseOff)
			}
			if l.(*DyldInfoOnly).BindOff > 0 {
				bindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).BindOff))
				if err != nil {
					return fmt.Errorf("failed to remap BindOff in %s: %v", types.LC_DYLD_INFO_ONLY, err)
				}
				l.(*DyldInfoOnly).BindOff = uint32(bindOff)
			}
			if l.(*DyldInfoOnly).WeakBindOff > 0 {
				weakBindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).WeakBindOff))
				if err != nil {
					return fmt.Errorf("failed to remap WeakBindOff in %s: %v", types.LC_DYLD_INFO_ONLY, err)
				}
				l.(*DyldInfoOnly).WeakBindOff = uint32(weakBindOff)
			}
			if l.(*DyldInfoOnly).LazyBindOff > 0 {
				lazyBindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).LazyBindOff))
				if err != nil {
					return fmt.Errorf("failed to remap LazyBindOff in %s: %v", types.LC_DYLD_INFO_ONLY, err)
				}
				l.(*DyldInfoOnly).LazyBindOff = uint32(lazyBindOff)
			}
			if l.(*DyldInfoOnly).ExportOff > 0 {
				exportOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).ExportOff))
				if err != nil {
					return fmt.Errorf("failed to remap ExportOff in %s: %v", types.LC_DYLD_INFO_ONLY, err)
				}
				l.(*DyldInfoOnly).ExportOff = uint32(exportOff)
			}
		case types.LC_FUNCTION_STARTS:
			off, err := segMap.Remap(uint64(l.(*FunctionStarts).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_FUNCTION_STARTS, err)
			}
			l.(*FunctionStarts).Offset = uint32(off)
		case types.LC_MAIN:
			// TODO:is this an offset or vmaddr ?
			off, err := segMap.Remap(l.(*EntryPoint).EntryOffset)
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_MAIN, err)
			}
			l.(*EntryPoint).EntryOffset = off
		case types.LC_DATA_IN_CODE:
			off, err := segMap.Remap(uint64(l.(*DataInCode).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_DATA_IN_CODE, err)
			}
			l.(*DataInCode).Offset = uint32(off)
		case types.LC_DYLIB_CODE_SIGN_DRS:
			off, err := segMap.Remap(uint64(l.(*DylibCodeSignDrs).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_DYLIB_CODE_SIGN_DRS, err)
			}
			l.(*DylibCodeSignDrs).Offset = uint32(off)
		case types.LC_ENCRYPTION_INFO_64:
			off, err := segMap.Remap(uint64(l.(*EncryptionInfo64).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_ENCRYPTION_INFO_64, err)
			}
			l.(*EncryptionInfo64).Offset = uint32(off)
		case types.LC_LINKER_OPTIMIZATION_HINT:
			off, err := segMap.Remap(uint64(l.(*LinkerOptimizationHint).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_LINKER_OPTIMIZATION_HINT, err)
			}
			l.(*LinkerOptimizationHint).Offset = uint32(off)
		case types.LC_DYLD_EXPORTS_TRIE:
			off, err := segMap.Remap(uint64(l.(*DyldExportsTrie).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_DYLD_EXPORTS_TRIE, err)
			}
			l.(*DyldExportsTrie).Offset = uint32(off)
		case types.LC_DYLD_CHAINED_FIXUPS:
			off, err := segMap.Remap(uint64(l.(*DyldChainedFixups).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_DYLD_CHAINED_FIXUPS, err)
			}
			l.(*DyldChainedFixups).Offset = uint32(off)
		case types.LC_FILESET_ENTRY:
			off, err := segMap.Remap(l.(*FilesetEntry).Offset)
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", types.LC_FILESET_ENTRY, err)
			}
			l.(*FilesetEntry).Offset = off
		default:
			return fmt.Errorf("found unknown load command %s", l.Command())
		}
	}
	return nil
}

func (f *File) optimizeLinkedit(locals []Symbol) ([]byte, error) {
	var lebuf bytes.Buffer

	linkedit := f.Segment("__LINKEDIT")
	if linkedit == nil {
		return nil, fmt.Errorf("unable to find __LINKEDIT segment")
	}

	for _, l := range f.Loads {
		switch l.Command() {
		case types.LC_CODE_SIGNATURE:
			panic("not implimented")
		case types.LC_SEGMENT_SPLIT_INFO:
			panic("not implimented")
		case types.LC_FUNCTION_STARTS:
			dat := make([]byte, l.(*FunctionStarts).Size)
			_, err := f.cr.ReadAt(dat, int64(l.(*FunctionStarts).Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to read load %s data: %v", l.Command(), err)
			}
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write load %s data:: %v", l.Command(), err)
			}
			pad := linkedit.Offset + uint64(lebuf.Len())%f.pointerSize()
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return nil, fmt.Errorf("failed to write load %s padding: %v", l.Command(), err)
			}

		case types.LC_DATA_IN_CODE:
			dat := make([]byte, l.(*DataInCode).Size)
			_, err := f.cr.ReadAt(dat, int64(l.(*DataInCode).Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to read load %s data: %v", l.Command(), err)
			}
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write load %s data:: %v", l.Command(), err)
			}
			pad := linkedit.Offset + uint64(lebuf.Len())%f.pointerSize()
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return nil, fmt.Errorf("failed to write load %s padding: %v", l.Command(), err)
			}
		case types.LC_DYLIB_CODE_SIGN_DRS:
			panic("not implimented")
		case types.LC_LINKER_OPTIMIZATION_HINT:
			panic("not implimented")
		case types.LC_DYLD_EXPORTS_TRIE:
			// panic("not implimented")
			exports, err := f.DyldExports()
			if err != nil {
				return nil, fmt.Errorf("failed to get %s exports: %v", l.Command(), err)
			}
			for _, exp := range exports {
				for idx, sym := range f.Symtab.Syms {
					if sym.Value == exp.Address {
						if f.Symtab.Syms[idx].Name == "<redacted>" {
							f.Symtab.Syms[idx].Name = exp.Name
						}
					}
				}
			}
		case types.LC_DYLD_CHAINED_FIXUPS:
			panic("not implimented")
		case types.LC_SYMTAB:
			// panic("not implimented")
			// symtab := l.(*Symtab)
			// symtab->nsyms = newSymCount;
			// symtab->symoff = (uint32_t)(newSymTabOffset + linkEditSegCmd->fileoff());
			// symtab->stroff = (uint32_t)(newStringPoolOffset + linkEditSegCmd->fileoff());
			// symtab->strsize = (uint32_t)newSymNames.size();
		case types.LC_DYSYMTAB:
			// panic("not implimented")
			// dynamicSymTab := l.(*Dysymtab)
			// dynamicSymTab->extreloff = 0;
			// dynamicSymTab->nextrel = 0;
			// dynamicSymTab->locreloff = 0;
			// dynamicSymTab->nlocrel = 0;
			// dynamicSymTab->indirectsymoff = (uint32_t)(newIndSymTabOffset + linkEditSegCmd->fileoff());
		}
	}

	return lebuf.Bytes(), nil
}

func (f *File) writeLoadCommands(buf *bytes.Buffer) error {
	for _, l := range f.Loads {
		switch l.Command() {
		case types.LC_SEGMENT:
			fallthrough
		case types.LC_SEGMENT_64:
			seg := l.(*Segment)
			if err := seg.Write(buf, f.ByteOrder); err != nil {
				return err
			}
			for i := uint32(0); i < seg.Nsect; i++ {
				if err := f.Sections[i+seg.Firstsect].Write(buf, f.ByteOrder); err != nil {
					return err
				}
			}
		case types.LC_SYMTAB:
			if err := l.(*Symtab).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_DYSYMTAB:
			if err := l.(*Dysymtab).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_CODE_SIGNATURE:
			if err := l.(*CodeSignature).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_SEGMENT_SPLIT_INFO:
			// <rdar://problem/23212513> dylibs iOS 9 dyld caches have bogus LC_SEGMENT_SPLIT_INFO
			// if err := l.(*SplitInfo).Write(buf, f.ByteOrder); err != nil {
			// 	return err
			// }
		case types.LC_ENCRYPTION_INFO:
			if err := l.(*EncryptionInfo).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_DYLD_INFO:
			if err := l.(*DyldInfo).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_DYLD_INFO_ONLY:
			if err := l.(*DyldInfoOnly).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_FUNCTION_STARTS:
			if err := l.(*FunctionStarts).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_MAIN:
			if err := l.(*EntryPoint).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_DATA_IN_CODE:
			if err := l.(*DataInCode).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_DYLIB_CODE_SIGN_DRS:
			if err := l.(*DylibCodeSignDrs).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_ENCRYPTION_INFO_64:
			if err := l.(*EncryptionInfo64).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_LINKER_OPTIMIZATION_HINT:
			if err := l.(*LinkerOptimizationHint).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_DYLD_EXPORTS_TRIE:
			if err := l.(*DyldExportsTrie).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_DYLD_CHAINED_FIXUPS:
			if err := l.(*DyldChainedFixups).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		case types.LC_FILESET_ENTRY:
			if err := l.(*FilesetEntry).Write(buf, f.ByteOrder); err != nil {
				return err
			}
		default:
			if _, err := buf.Write(l.Raw()); err != nil {
				return fmt.Errorf("failed to write %s to buffer: %v", l.Command().String(), err)
			}
		}
	}
	return nil
}
