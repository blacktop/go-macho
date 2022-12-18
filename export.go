package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
)

var reexportDeps uint64

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
	return 0, fmt.Errorf("failed to remap offset %#x", offset)
}

func (m exportSegMap) RemapSeg(name string, offset uint64) (uint64, uint64, error) {
	for _, segInfo := range m {
		if segInfo.Name == name {
			return segInfo.New.Start + (offset - segInfo.Old.Start), (segInfo.New.End - segInfo.New.Start), nil
		}
	}
	return 0, 0, fmt.Errorf("failed to remap offset %#x", offset)
}

func pageAlign(offset uint64) uint64 {
	return offset + (0x1000 - (offset % 0x1000))
}

// Export exports an in-memory or cached dylib|kext MachO to a file
func (f *File) Export(path string, dcf *fixupchains.DyldChainedFixups, baseAddress uint64, locals []Symbol) (err error) {
	var buf bytes.Buffer
	var lebuf *bytes.Buffer
	var segMap exportSegMap

	inCache := f.FileHeader.Flags.DylibInCache()

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
				End:   newSegOffset + pageAlign(seg.Filesz),
			},
		})
		newSegOffset += pageAlign(seg.Filesz)
	}

	sort.Sort(segMap)

	if err := f.optimizeLoadCommands(segMap); err != nil {
		return fmt.Errorf("failed to optimize load commands: %v", err)
	}

	if inCache {
		lebuf, err = f.optimizeLinkedit(locals)
		if err != nil {
			return fmt.Errorf("failed to optimize load commands: %v", err)
		}
	}

	if err := f.optimizeObjC(segMap); err != nil {
		return fmt.Errorf("failed to optimize ObjC: %v", err)
	}

	if inCache {
		f.FileHeader.Flags &= 0x7FFFFFFF // remove in-cache bit
	}

	if err := f.FileHeader.Write(&buf, f.ByteOrder); err != nil {
		return fmt.Errorf("failed to write file header to buffer: %v", err)
	}

	if err := f.writeLoadCommands(&buf); err != nil {
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
				if inCache {
					if _, err := buf.Write(lebuf.Bytes()); err != nil {
						return fmt.Errorf("failed to write optimized segment %s to export buffer: %v", seg.Name, err)
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

	os.MkdirAll(filepath.Dir(path), os.ModePerm)

	if err := os.WriteFile(path, buf.Bytes(), 0755); err != nil {
		return fmt.Errorf("failed to write exported MachO to file %s: %v", path, err)
	}

	// FIXME: fixup chains are not yet supported (this should be done in the linkedit optimization step and create a REAL LC_DYLD_CHAINED_FIXUPS load command)
	// if dcf != nil {
	// 	newFile, err := os.OpenFile(path, os.O_WRONLY, 0755)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to open exported MachO %s: %v", path, err)
	// 	}
	// 	defer newFile.Close()

	// 	fi, err := newFile.Stat()
	// 	if err != nil {
	// 		return fmt.Errorf("failed to stat file %s: %v", path, err)
	// 	}
	// 	fileSize := fi.Size()

	// 	for _, start := range dcf.Starts {
	// 		if start.PageStarts != nil {
	// 			for _, fixup := range start.Fixups {
	// 				off, err := segMap.Remap(fixup.Offset())
	// 				if err != nil {
	// 					continue
	// 				}

	// 				if off == 0 || off >= uint64(fileSize) {
	// 					continue
	// 				}

	// 				if _, err := newFile.Seek(int64(off), io.SeekStart); err != nil {
	// 					return fmt.Errorf("failed to seek in exported file to offset %#x from the start: %v", off, err)
	// 				}

	// 				switch fx := fixup.(type) {
	// 				case fixupchains.Bind:
	// 					// var addend string
	// 					// addr := uint64(f.Offset()) + m.GetBaseAddress()
	// 					// if fullAddend := dcf.Imports[f.Ordinal()].Addend() + f.Addend(); fullAddend > 0 {
	// 					// 	addend = fmt.Sprintf(" + %#x", fullAddend)
	// 					// 	addr += fullAddend
	// 					// }
	// 					// sec = m.FindSectionForVMAddr(addr)
	// 					// lib := m.LibraryOrdinalName(dcf.Imports[f.Ordinal()].LibOrdinal())
	// 					// if sec != nil && sec != lastSec {
	// 					// 	fmt.Printf("%s.%s\n", sec.Seg, sec.Name)
	// 					// }
	// 					// fmt.Printf("%s\t%s/%s%s\n", fixupchains.Bind(f).String(m.GetBaseAddress()), lib, f.Name(), addend)
	// 				case fixupchains.Rebase:
	// 					addr := uint64(fx.Target()) + baseAddress
	// 					if err := binary.Write(newFile, f.ByteOrder, addr); err != nil {
	// 						return fmt.Errorf("failed to write fixup address %#x: %v", addr, err)
	// 					}
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	return nil
}

func (f *File) optimizeLoadCommands(segMap exportSegMap) error {
	var depIndex uint64
	for _, l := range f.Loads {
		switch l.Command() {
		case types.LC_SEGMENT:
			fallthrough
		case types.LC_SEGMENT_64:
			seg := l.(*Segment)

			off, sz, err := segMap.RemapSeg(seg.Name, seg.Offset)
			if err != nil {
				return fmt.Errorf("failed to remap offset in segment %s: %v", seg.Name, err)
			}
			seg.Offset = off
			seg.Filesz = sz
			seg.Memsz = sz

			for i := uint32(0); i < seg.Nsect; i++ {
				if f.Sections[i+seg.Firstsect].Offset != 0 {
					off, err := segMap.Remap(uint64(f.Sections[i+seg.Firstsect].Offset))
					if err != nil {
						// return fmt.Errorf("failed to remap offset in section %s.%s: %v", seg.Name, f.Sections[i+seg.Firstsect].Name, err)
						continue // FIXME: this is so that libcorecrypto.dylib will work as it has normal offsets for some reason
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
			// symtab := l.(*Symtab)
			// _ = symtab
			// symoff, err := segMap.Remap(uint64(l.(*Symtab).Symoff))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap symbol offset in %s: %v", l.Command(), err)
			// }
			// stroff, err := segMap.Remap(uint64(l.(*Symtab).Stroff))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap string offset in %s: %v", l.Command(), err)
			// }
			// l.(*Symtab).Symoff = uint32(symoff)
			// l.(*Symtab).Stroff = uint32(stroff)
		case types.LC_DYSYMTAB:
			// if l.(*Dysymtab).Tocoffset > 0 {
			// 	tocoffset, err := segMap.Remap(uint64(l.(*Dysymtab).Tocoffset))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap Tocoffset in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*Dysymtab).Tocoffset = uint32(tocoffset)
			// }
			// if l.(*Dysymtab).Modtaboff > 0 {
			// 	modtaboff, err := segMap.Remap(uint64(l.(*Dysymtab).Modtaboff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap Modtaboff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*Dysymtab).Modtaboff = uint32(modtaboff)
			// }
			// if l.(*Dysymtab).Extrefsymoff > 0 {
			// 	extrefsymoff, err := segMap.Remap(uint64(l.(*Dysymtab).Extrefsymoff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap Extrefsymoff %s: %v", l.Command(), err)
			// 	}
			// 	l.(*Dysymtab).Extrefsymoff = uint32(extrefsymoff)
			// }
			// if l.(*Dysymtab).Indirectsymoff > 0 {
			// 	indirectsymoff, err := segMap.Remap(uint64(l.(*Dysymtab).Indirectsymoff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap Indirectsymoff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*Dysymtab).Indirectsymoff = uint32(indirectsymoff)
			// }
			// if l.(*Dysymtab).Extreloff > 0 {
			// 	extreloff, err := segMap.Remap(uint64(l.(*Dysymtab).Extreloff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap Extreloff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*Dysymtab).Extreloff = uint32(extreloff)
			// }
			// if l.(*Dysymtab).Locreloff > 0 {
			// 	locreloff, err := segMap.Remap(uint64(l.(*Dysymtab).Locreloff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap Locreloff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*Dysymtab).Locreloff = uint32(locreloff)
			// }
		case types.LC_CODE_SIGNATURE:
			// off, err := segMap.Remap(uint64(l.(*CodeSignature).Offset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			// }
			// l.(*CodeSignature).Offset = uint32(off)
		case types.LC_SEGMENT_SPLIT_INFO:
			// <rdar://problem/23212513> dylibs iOS 9 dyld caches have bogus LC_SEGMENT_SPLIT_INFO
			// off, err := segMap.Remap(uint64(l.(*SplitInfo).Offset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			// }
			// l.(*SplitInfo).Offset = uint32(off)
		case types.LC_ENCRYPTION_INFO:
			off, err := segMap.Remap(uint64(l.(*EncryptionInfo).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*EncryptionInfo).Offset = uint32(off)
		case types.LC_DYLD_INFO:
			// if l.(*DyldInfo).RebaseOff > 0 {
			// 	rebaseOff, err := segMap.Remap(uint64(l.(*DyldInfo).RebaseOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap RebaseOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfoOnly).RebaseOff = uint32(rebaseOff)
			// }
			// if l.(*DyldInfoOnly).BindOff > 0 {
			// 	bindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).BindOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap BindOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfoOnly).BindOff = uint32(bindOff)
			// }
			// if l.(*DyldInfo).WeakBindOff > 0 {
			// 	weakBindOff, err := segMap.Remap(uint64(l.(*DyldInfo).WeakBindOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap WeakBindOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfo).WeakBindOff = uint32(weakBindOff)
			// }
			// if l.(*DyldInfo).LazyBindOff > 0 {
			// 	lazyBindOff, err := segMap.Remap(uint64(l.(*DyldInfo).LazyBindOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap LazyBindOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfo).LazyBindOff = uint32(lazyBindOff)
			// }
			// if l.(*DyldInfo).ExportOff > 0 {
			// 	exportOff, err := segMap.Remap(uint64(l.(*DyldInfo).ExportOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap ExportOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfo).ExportOff = uint32(exportOff)
			// }
		case types.LC_DYLD_INFO_ONLY:
			// if l.(*DyldInfoOnly).RebaseOff > 0 {
			// 	rebaseOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).RebaseOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap RebaseOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfoOnly).RebaseOff = uint32(rebaseOff)
			// }
			// if l.(*DyldInfoOnly).BindOff > 0 {
			// 	bindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).BindOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap BindOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfoOnly).BindOff = uint32(bindOff)
			// }
			// if l.(*DyldInfoOnly).WeakBindOff > 0 {
			// 	weakBindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).WeakBindOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap WeakBindOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfoOnly).WeakBindOff = uint32(weakBindOff)
			// }
			// if l.(*DyldInfoOnly).LazyBindOff > 0 {
			// 	lazyBindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).LazyBindOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap LazyBindOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfoOnly).LazyBindOff = uint32(lazyBindOff)
			// }
			// if l.(*DyldInfoOnly).ExportOff > 0 {
			// 	exportOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).ExportOff))
			// 	if err != nil {
			// 		return fmt.Errorf("failed to remap ExportOff in %s: %v", l.Command(), err)
			// 	}
			// 	l.(*DyldInfoOnly).ExportOff = uint32(exportOff)
			// }
		case types.LC_FUNCTION_STARTS:
			// off, err := segMap.Remap(uint64(l.(*FunctionStarts).Offset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			// }
			// l.(*FunctionStarts).Offset = uint32(off)
		case types.LC_MAIN:
			// TODO:is this an offset or vmaddr ?
			off, err := segMap.Remap(l.(*EntryPoint).EntryOffset)
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*EntryPoint).EntryOffset = off
		case types.LC_DATA_IN_CODE:
			// off, err := segMap.Remap(uint64(l.(*DataInCode).Offset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			// }
			// l.(*DataInCode).Offset = uint32(off)
		case types.LC_DYLIB_CODE_SIGN_DRS:
			off, err := segMap.Remap(uint64(l.(*DylibCodeSignDrs).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*DylibCodeSignDrs).Offset = uint32(off)
		case types.LC_ENCRYPTION_INFO_64:
			off, err := segMap.Remap(uint64(l.(*EncryptionInfo64).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*EncryptionInfo64).Offset = uint32(off)
		case types.LC_LINKER_OPTIMIZATION_HINT:
			off, err := segMap.Remap(uint64(l.(*LinkerOptimizationHint).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*LinkerOptimizationHint).Offset = uint32(off)
		case types.LC_DYLD_EXPORTS_TRIE:
			// off, err := segMap.Remap(uint64(l.(*DyldExportsTrie).Offset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			// }
			// l.(*DyldExportsTrie).Offset = uint32(off)
		case types.LC_DYLD_CHAINED_FIXUPS:
			off, err := segMap.Remap(uint64(l.(*DyldChainedFixups).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*DyldChainedFixups).Offset = uint32(off)
		case types.LC_FILESET_ENTRY:
			off, err := segMap.Remap(l.(*FilesetEntry).Offset)
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*FilesetEntry).Offset = off
		case types.LC_LOAD_DYLIB:
			fallthrough
		case types.LC_LOAD_WEAK_DYLIB:
			fallthrough
		case types.LC_REEXPORT_DYLIB:
			fallthrough
		case types.LC_LOAD_UPWARD_DYLIB:
			depIndex++
			if l.Command() == types.LC_REEXPORT_DYLIB {
				reexportDeps = depIndex
			}
		}
	}
	return nil
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

func (f *File) optimizeLinkedit(locals []Symbol) (*bytes.Buffer, error) {
	var err error
	var newSymCount uint32
	var lebuf bytes.Buffer
	var newSymNames bytes.Buffer
	var exports []trie.TrieExport

	linkedit := f.Segment("__LINKEDIT")
	if linkedit == nil {
		return nil, fmt.Errorf("unable to find __LINKEDIT segment")
	}

	// fix LC_DYLD_INFO|LC_DYLD_INFO_ONLY
	if dinfo := f.DyldInfo(); dinfo != nil {
		if dinfo.RebaseSize > 0 {
			dat := make([]byte, dinfo.RebaseSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.RebaseOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s rebase data: %v", dinfo.LoadCmd, err)
			}
			dinfo.RebaseOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s rebase data: %v", dinfo.LoadCmd, err)
			}
		}
		if dinfo.BindSize > 0 {
			dat := make([]byte, dinfo.BindSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.BindOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s bind data: %v", dinfo.LoadCmd, err)
			}
			dinfo.BindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s bind data: %v", dinfo.LoadCmd, err)
			}
		}
		if dinfo.WeakBindSize > 0 {
			dat := make([]byte, dinfo.WeakBindSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.WeakBindOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s weak bind data: %v", dinfo.LoadCmd, err)
			}
			dinfo.WeakBindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s weak bind data: %v", dinfo.LoadCmd, err)
			}
		}
		if dinfo.LazyBindSize > 0 {
			dat := make([]byte, dinfo.LazyBindSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.LazyBindOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s lazy bind data: %v", dinfo.LoadCmd, err)
			}
			dinfo.LazyBindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s lazy bind data: %v", dinfo.LoadCmd, err)
			}
		}
		if dinfo.ExportSize > 0 {
			dat := make([]byte, dinfo.ExportSize)
			if _, err := f.cr.ReadAt(dat, int64(dinfo.ExportOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s export data: %v", dinfo.LoadCmd, err)
			}
			dinfo.ExportOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s export data: %v", dinfo.LoadCmd, err)
			}
		}
	} else if dionly := f.DyldInfoOnly(); dionly != nil {
		if dionly.RebaseSize > 0 {
			dat := make([]byte, dionly.RebaseSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.RebaseOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s rebase data: %v", dionly.LoadCmd, err)
			}
			dionly.RebaseOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s rebase data: %v", dionly.LoadCmd, err)
			}
		}
		if dionly.BindSize > 0 {
			dat := make([]byte, dionly.BindSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.BindOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s bind data: %v", dionly.LoadCmd, err)
			}
			dionly.BindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s bind data: %v", dionly.LoadCmd, err)
			}
		}
		if dionly.WeakBindSize > 0 {
			dat := make([]byte, dionly.WeakBindSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.WeakBindOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s weak bind data: %v", dionly.LoadCmd, err)
			}
			dionly.WeakBindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s weak bind data: %v", dionly.LoadCmd, err)
			}
		}
		if dionly.LazyBindSize > 0 {
			dat := make([]byte, dionly.LazyBindSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.LazyBindOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s lazy bind data: %v", dionly.LoadCmd, err)
			}
			dionly.LazyBindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s lazy bind data: %v", dionly.LoadCmd, err)
			}
		}
		if dionly.ExportSize > 0 {
			dat := make([]byte, dionly.ExportSize)
			if _, err := f.cr.ReadAt(dat, int64(dionly.ExportOff)); err != nil {
				return nil, fmt.Errorf("failed to read %s export data: %v", dionly.LoadCmd, err)
			}
			dionly.ExportOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s export data: %v", dionly.LoadCmd, err)
			}
		}
		pad := linkedit.Offset + (uint64(lebuf.Len()) % f.pointerSize())
		if _, err := lebuf.Write(make([]byte, pad)); err != nil {
			return nil, fmt.Errorf("failed to write LC_DYLD_INFO|LC_DYLD_INFO_ONLY padding: %v", err)
		}
	}
	// fix LC_FUNCTION_STARTS
	if fstarts := f.FunctionStarts(); fstarts != nil {
		dat := make([]byte, fstarts.Size)
		if _, err := f.cr.ReadAt(dat, int64(fstarts.Offset)); err != nil {
			return nil, fmt.Errorf("failed to read LC_FUNCTION_STARTS data: %v", err)
		}
		fstarts.Offset = uint32(linkedit.Offset) + uint32(lebuf.Len())
		if _, err := lebuf.Write(dat); err != nil {
			return nil, fmt.Errorf("failed to write LC_FUNCTION_STARTS data: %v", err)
		}
		pad := linkedit.Offset + (uint64(lebuf.Len()) % f.pointerSize())
		if _, err := lebuf.Write(make([]byte, pad)); err != nil {
			return nil, fmt.Errorf("failed to write LC_FUNCTION_STARTS padding: %v", err)
		}
	}
	// fix LC_DATA_IN_CODE
	if dataNCode := f.DataInCode(); dataNCode != nil {
		dat := make([]byte, dataNCode.Size)
		if _, err = f.cr.ReadAt(dat, int64(dataNCode.Offset)); err != nil {
			return nil, fmt.Errorf("failed to read LC_DATA_IN_CODE data: %v", err)
		}
		dataNCode.Offset = uint32(linkedit.Offset) + uint32(lebuf.Len())
		if _, err := lebuf.Write(dat); err != nil {
			return nil, fmt.Errorf("failed to write LC_DATA_IN_CODE data: %v", err)
		}
		pad := linkedit.Offset + (uint64(lebuf.Len()) % f.pointerSize())
		if _, err := lebuf.Write(make([]byte, pad)); err != nil {
			return nil, fmt.Errorf("failed to write LC_DATA_IN_CODE padding: %v", err)
		}
	}
	// fix LC_DYLD_EXPORTS_TRIE
	if dexpTrie := f.DyldExportsTrie(); dexpTrie != nil {
		exports, err = f.DyldExports()
		if err != nil {
			return nil, fmt.Errorf("failed to get LC_DYLD_EXPORTS_TRIE exports: %v", err)
		}
		dat := make([]byte, dexpTrie.Size)
		if _, err = f.cr.ReadAt(dat, int64(dexpTrie.Offset)); err != nil {
			return nil, fmt.Errorf("failed to read LC_DYLD_EXPORTS_TRIE data: %v", err)
		}
		dexpTrie.Offset = uint32(linkedit.Offset) + uint32(lebuf.Len())
		if _, err := lebuf.Write(dat); err != nil {
			return nil, fmt.Errorf("failed to write LC_DYLD_EXPORTS_TRIE data: %v", err)
		}
		pad := linkedit.Offset + (uint64(lebuf.Len()) % f.pointerSize())
		if _, err := lebuf.Write(make([]byte, pad)); err != nil {
			return nil, fmt.Errorf("failed to write LC_DYLD_EXPORTS_TRIE padding: %v", err)
		}
	}

	// TODO: LC_CODE_SIGNATURE           ?
	// TODO: LC_DYLIB_CODE_SIGN_DRS      ?
	// TODO: LC_LINKER_OPTIMIZATION_HINT ?
	// TODO: LC_DYLD_CHAINED_FIXUPS      ?

	newSymTabOffset := uint64(lebuf.Len())

	// first pool entry is always empty string
	newSymNames.WriteString("\x00")
	// local symbols are first in dylibs, if this cache has unmapped locals, insert them all first
	for _, lsym := range locals {
		if err := binary.Write(&lebuf, binary.LittleEndian, types.Nlist64{
			Nlist: types.Nlist{
				Name: uint32(newSymNames.Len()),
				Type: lsym.Type,
				Sect: lsym.Sect,
				Desc: lsym.Desc,
			},
			Value: lsym.Value,
		}); err != nil {
			return nil, fmt.Errorf("failed to write local nlist entry to NEW linkedit data: %v", err)
		}
		if _, err := newSymNames.WriteString(lsym.Name + "\x00"); err != nil {
			return nil, fmt.Errorf("failed to write local symbol name string to NEW linkedit data: %v", err)
		}
		newSymCount++
	}
	// now start copying symbol table from start of externs instead of start of locals
	// for _, sym := range f.Symtab.Syms[f.Dysymtab.Iextdefsym:] {
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			if err := binary.Write(&lebuf, binary.LittleEndian, types.Nlist64{
				Nlist: types.Nlist{
					Name: uint32(newSymNames.Len()),
					Type: sym.Type,
					Sect: sym.Sect,
					Desc: sym.Desc,
				},
				Value: sym.Value,
			}); err != nil {
				return nil, fmt.Errorf("failed to write symtab nlist entry to NEW linkedit data: %v", err)
			}
			if _, err := newSymNames.WriteString(sym.Name + "\x00"); err != nil {
				return nil, fmt.Errorf("failed to write symbol name string to NEW linkedit data: %v", err)
			}
			newSymCount++
		}
	}
	// get all re-exports from LC_DYLD_EXPORTS_TRIE
	for _, exp := range exports {
		// If the symbol comes from a dylib that is re-exported, this is not an individual symbol re-export
		// if ( _reexportDeps.count((int)entry.info.other) != 0 )
		//     return true;
		// if !exp.Flags.Regular() || exp.Flags.ReExport() || reexportDeps == exp.Other {
		if !exp.Flags.Regular() || exp.Flags.ReExport() {
			if err := binary.Write(&lebuf, binary.LittleEndian, types.Nlist64{
				Nlist: types.Nlist{
					Name: uint32(newSymNames.Len()),
					Type: (types.N_INDR | types.N_EXT),
					Sect: 0,
					Desc: 0,
				},
				Value: exp.Address,
			}); err != nil {
				return nil, fmt.Errorf("failed to write export nlist entry to NEW linkedit data: %v", err)
			}
			if _, err := newSymNames.WriteString(exp.Name + "\x00"); err != nil {
				return nil, fmt.Errorf("failed to write export symbol name string to NEW linkedit data: %v", err)
			}
			if _, err := newSymNames.WriteString(exp.ReExport + "\x00"); err != nil {
				return nil, fmt.Errorf("failed to write symbol reexport name string to NEW linkedit data: %v", err)
			}
			newSymCount++
		}
	}

	pad := linkedit.Offset + (uint64(lebuf.Len()) % f.pointerSize())
	if _, err := lebuf.Write(make([]byte, pad)); err != nil {
		return nil, fmt.Errorf("failed to write symtab padding: %v", err)
	}

	newIndSymTabOffset := uint64(lebuf.Len())

	// Copy (and adjust) indirect symbol table
	var undefSymbolShift uint32
	if len(locals) > 0 {
		undefSymbolShift = uint32(len(locals)) - f.Dysymtab.Nlocalsym
	}
	if undefSymbolShift > 0 {
		for idx, indSym := range f.Dysymtab.IndirectSyms {
			f.Dysymtab.IndirectSyms[idx] = indSym + undefSymbolShift
		}
	}
	if err := binary.Write(&lebuf, binary.LittleEndian, f.Dysymtab.IndirectSyms); err != nil {
		return nil, fmt.Errorf("failed to write indirect symbol table to NEW linkedit data: %v", err)
	}

	pad = linkedit.Offset + (uint64(lebuf.Len()) % f.pointerSize())
	if _, err := lebuf.Write(make([]byte, pad)); err != nil {
		return nil, fmt.Errorf("failed to write indirect symtab padding: %v", err)
	}

	newStringPoolOffset := uint64(lebuf.Len())

	// pointer align string pool size
	for (uint64(newSymNames.Len()) % f.pointerSize()) != 0 {
		newSymNames.WriteString("\x00")
	}
	// Copy sym names
	if _, err := lebuf.Write(newSymNames.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write symbol name strings to NEW linkedit data: %v", err)
	}

	if f.Symtab != nil {
		f.Symtab.Nsyms = newSymCount
		f.Symtab.Symoff = uint32(linkedit.Offset + newSymTabOffset)
		f.Symtab.Stroff = uint32(linkedit.Offset + newStringPoolOffset)
		f.Symtab.Strsize = uint32(newSymNames.Len())
	}
	// f.Dysymtab.Ilocalsym = uint32(len(locals)) + f. .Nextdefsym + f.Dysymtab.Nundefsym
	// f.Dysymtab.Nlocalsym = uint32(len(locals))
	// f.Dysymtab.Iextdefsym = uint32(len(locals))
	// f.Dysymtab.Iundefsym = f.Dysymtab.Iextdefsym + f.Dysymtab.Nextdefsym
	// f.Dysymtab.Extreloff = 0
	// f.Dysymtab.Nextrel = 0
	// f.Dysymtab.Locreloff = 0
	// f.Dysymtab.Nlocrel = 0
	f.Dysymtab.Indirectsymoff = uint32(linkedit.Offset + newIndSymTabOffset)

	linkedit.Filesz = pageAlign(uint64(f.Symtab.Stroff + f.Symtab.Strsize))
	linkedit.Memsz = linkedit.Filesz

	if linkedit.Filesz > uint64(lebuf.Len()) {
		pad = linkedit.Filesz - uint64(lebuf.Len())
		if _, err := lebuf.Write(make([]byte, pad)); err != nil {
			return nil, fmt.Errorf("failed to write linkedit segment padding: %v", err)
		}
	}

	return &lebuf, nil
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
			if err := l.(*SplitInfo).Write(buf, f.ByteOrder); err != nil {
				return err
			}
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
