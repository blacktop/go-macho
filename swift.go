package macho

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"

	"github.com/blacktop/go-macho/types/swift"
)

const sizeOfInt32 = 4
const sizeOfInt64 = 8

var ErrSwiftSectionError = fmt.Errorf("missing swift section")

// HasSwift checks if the MachO has swift info
func (f *File) HasSwift() bool {
	if info, err := f.GetObjCImageInfo(); err == nil {
		if info != nil && info.HasSwift() {
			return true
		}
	}
	return false
}

// GetSwiftTOC returns a table of contents of the Swift objects in the MachO
func (f *File) GetSwiftTOC() swift.TOC {
	var toc swift.TOC
	for _, sec := range f.Sections {
		switch sec.Name {
		case "__swift5_builtin":
			toc.Builtins = int(sec.Size) / binary.Size(swift.BuiltinTypeDescriptor{})
		// case "__swift5_fieldmd":
		// 	toc.Fields = sec.Size / f.pointerSize()
		case "__swift5_types":
			toc.Types += int(sec.Size / sizeOfInt32)
		case "__swift5_types2":
			toc.Types += int(sec.Size / sizeOfInt32)
		// case "__swift5_assocty":
		// 	toc.AssociatedTypes = sec.Size / f.pointerSize()
		case "__swift5_protos":
			toc.Protocols = int(sec.Size / sizeOfInt32)
		case "__swift5_proto":
			toc.ProtocolConformances = int(sec.Size / sizeOfInt32)
		}
	}
	return toc
}

// GetSwiftEntry parses the __TEXT.__swift5_entry section
func (f *File) GetSwiftEntry() (uint64, error) {
	if sec := f.Section("__TEXT", "__swift5_entry"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return 0, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return 0, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		var swiftEntry int32
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &swiftEntry); err != nil {
			return 0, fmt.Errorf("failed to read __swift5_entry data: %v", err)
		}

		return sec.Addr + uint64(swiftEntry), nil
	}

	return 0, fmt.Errorf("MachO has no '__swift5_entry' section: %w", ErrSwiftSectionError)
}

// GetSwiftBuiltinTypes parses all the built-in types in the __TEXT.__swift5_builtin section
func (f *File) GetSwiftBuiltinTypes() (builtins []swift.BuiltinType, err error) {
	if sec := f.Section("__TEXT", "__swift5_builtin"); sec != nil {
		f.cr.SeekToAddr(sec.Addr)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %w", sec.Seg, sec.Name, err)
		}

		btypes := make([]swift.BuiltinTypeDescriptor, int(sec.Size)/binary.Size(swift.BuiltinTypeDescriptor{}))

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &btypes); err != nil {
			return nil, fmt.Errorf("failed to read []swift.BuiltinTypeDescriptor: %w", err)
		}

		for idx, btype := range btypes {
			currAddr := sec.Addr + uint64(idx*binary.Size(swift.BuiltinTypeDescriptor{}))

			name, err := f.makeSymbolicMangledNameStringRef(uint64(int64(currAddr) + int64(btype.TypeName)))
			if err != nil {
				return nil, fmt.Errorf("failed to read builtin type name: %w", err)
			}

			builtins = append(builtins, swift.BuiltinType{
				BuiltinTypeDescriptor: btype,
				Address:               currAddr,
				Name:                  name,
			})
		}

		return builtins, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_builtin' section: %w", ErrSwiftSectionError)
}

// GetSwiftReflectionStrings parses all the reflection strings in the __TEXT.__swift5_reflstr section
func (f *File) GetSwiftReflectionStrings() (map[uint64]string, error) {
	reflStrings := make(map[uint64]string)
	if sec := f.Section("__TEXT", "__swift5_reflstr"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %w", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %w", sec.Seg, sec.Name, err)
		}

		r := bytes.NewBuffer(dat)

		for {
			s, err := r.ReadString('\x00')
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift reflection string: %w", err)
			}

			if len(strings.Trim(s, "\x00")) > 0 {
				reflStrings[sec.Addr+(sec.Size-uint64(r.Len()+len(s)))] = strings.Trim(s, "\x00")
			}
		}

		return reflStrings, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_reflstr' section: %w", ErrSwiftSectionError)
}

// GetSwiftFields parses all the fields in the __TEXT.__swift5_fields section
func (f *File) GetSwiftFields() (fields []swift.Field, err error) {
	if sec := f.Section("__TEXT", "__swift5_fieldmd"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}

		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		// read field descriptors
		for {
			curr, _ := r.Seek(0, io.SeekCurrent)

			field, err := f.readField(r, sec.Addr+uint64(curr))
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift field at address %#x: %w", sec.Addr+uint64(curr), err)
			}

			fields = append(fields, *field)
		}

		return fields, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_fieldmd' section: %w", ErrSwiftSectionError)
}

func (f *File) readField(r io.ReadSeeker, addr uint64) (field *swift.Field, err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	field = &swift.Field{Address: addr}

	if err := field.FieldDescriptor.Read(r, addr); err != nil {
		return nil, fmt.Errorf("failed to read swift field descriptor string: %w", err)
	}

	field.Records = make([]swift.FieldRecord, field.NumFields)

	for i := 0; i < int(field.NumFields); i++ {
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := field.Records[i].FieldRecordDescriptor.Read(r, field.Address+uint64(curr-off)); err != nil {
			return nil, fmt.Errorf("failed to read swift FieldRecordDescriptor: %v", err)
		}
	}

	if field.MangledTypeNameOffset.IsSet() {
		field.Type, err = f.makeSymbolicMangledNameStringRef(field.MangledTypeNameOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift field mangled type name: %w", err)
		}
	}

	if field.SuperclassOffset.IsSet() {
		field.SuperClass, err = f.makeSymbolicMangledNameStringRef(field.SuperclassOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift field super class mangled name: %w", err)
		}
	}

	for idx, rec := range field.Records {
		field.Records[idx].Name, err = f.GetCString(rec.FieldNameOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift field record name cstring: %w", err)
		}

		if rec.MangledTypeNameOffset.IsSet() {
			field.Records[idx].MangledType, err = f.makeSymbolicMangledNameStringRef(rec.MangledTypeNameOffset.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("failed to read swift field record mangled type name; %w", err)
			}
		}
	}

	f.swift[field.Address] = field // cache field

	return field, nil
}

// GetSwiftAssociatedTypes parses all the associated types in the __TEXT.__swift5_assocty section
func (f *File) GetSwiftAssociatedTypes() (asstypes []swift.AssociatedType, err error) {
	if sec := f.Section("__TEXT", "__swift5_assocty"); sec != nil {
		f.cr.SeekToAddr(sec.Addr)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %w", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			curr, _ := r.Seek(0, io.SeekCurrent)

			atyp := swift.AssociatedType{
				Address: sec.Addr + uint64(curr),
			}

			err = atyp.AssociatedTypeDescriptor.Read(r, sec.Addr+uint64(curr))
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift AssociatedTypeDescriptor: %w", err)
			}

			atyp.TypeRecords = make([]swift.ATRecordType, atyp.NumAssociatedTypes)
			for i := uint32(0); i < atyp.NumAssociatedTypes; i++ {
				curr, _ = r.Seek(0, io.SeekCurrent)
				if err := atyp.TypeRecords[i].AssociatedTypeRecord.Read(r, sec.Addr+uint64(curr)); err != nil {
					return nil, fmt.Errorf("failed to read AssociatedTypeRecord: %w", err)
				}
			}

			atyp.ConformingTypeName, err = f.makeSymbolicMangledNameStringRef(atyp.ConformingTypeNameOffset.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("failed to read conforming type for associated type at addr %#x: %v", atyp.ConformingTypeNameOffset.GetAddress(), err)
			}

			atyp.ProtocolTypeName, err = f.makeSymbolicMangledNameStringRef(atyp.ProtocolTypeNameOffset.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("failed to read swift assocated type protocol type name at addr %#x: %v", atyp.ProtocolTypeNameOffset.GetAddress(), err)
			}

			for idx, rec := range atyp.TypeRecords {
				atyp.TypeRecords[idx].Name, err = f.GetCString(rec.NameOffset.GetAddress())
				if err != nil {
					return nil, fmt.Errorf("failed to read associated type record name: %w", err)
				}
				atyp.TypeRecords[idx].SubstitutedTypeName, err = f.makeSymbolicMangledNameStringRef(rec.SubstitutedTypeNameOffset.GetAddress())
				if err != nil {
					return nil, fmt.Errorf("failed to read associated type substituted type name: %w", err)
				}
			}

			asstypes = append(asstypes, atyp)
		}

		return asstypes, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_assocty' section: %w", ErrSwiftSectionError)
}

// GetSwiftProtocols parses all the protocols in the __TEXT.__swift5_protos section
func (f *File) GetSwiftProtocols() (protos []swift.Protocol, err error) {
	if sec := f.Section("__TEXT", "__swift5_protos"); sec != nil {
		f.cr.SeekToAddr(sec.Addr)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %w", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		relOffsets := make([]swift.RelativeIndirectablePointer, len(dat)/sizeOfInt32)
		for i := 0; i < len(dat)/sizeOfInt32; i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			relOffsets[i].Address = sec.Addr + uint64(curr)
			if err := binary.Read(r, f.ByteOrder, &relOffsets[i].RelOff); err != nil {
				return nil, fmt.Errorf("failed to read relative offsets: %v", err)
			}
		}

		for _, relOff := range relOffsets {
			addr, err := relOff.GetAddress(f.GetPointerAtAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to get swift protocol address from relative indirectable pointer: %v", err)
			}

			if typ, ok := f.swift[addr]; ok { // check cache
				if typ, ok := typ.(*swift.Type); ok {
					if typ.Kind == swift.CDKindProtocol {
						protos = append(protos, typ.Type.(swift.Protocol))
					}
				}
			} else {
				if err := f.cr.SeekToAddr(addr); err != nil {
					return nil, fmt.Errorf("failed to seek to swift protocol address %#x: %v", addr, err)
				}

				proto, err := f.parseProtocol(f.cr, &swift.Type{Address: addr})
				if err != nil {
					return nil, fmt.Errorf("failed to read swift protocol at address %#x: %w", addr, err)
				}

				protos = append(protos, *proto)
			}
		}

		return protos, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_protos' section: %w", ErrSwiftSectionError)
}

// GetSwiftProtocolConformances parses all the protocol conformances in the __TEXT.__swift5_proto section
func (f *File) GetSwiftProtocolConformances() (protoConfDescs []swift.ConformanceDescriptor, err error) {
	if sec := f.Section("__TEXT", "__swift5_proto"); sec != nil {
		f.cr.SeekToAddr(sec.Addr)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %w", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		relOffsets := make([]swift.RelativeIndirectablePointer, len(dat)/sizeOfInt32)
		for i := 0; i < len(dat)/sizeOfInt32; i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			relOffsets[i].Address = sec.Addr + uint64(curr)
			if err := binary.Read(r, f.ByteOrder, &relOffsets[i].RelOff); err != nil {
				return nil, fmt.Errorf("failed to read relative offsets: %v", err)
			}
		}

		for _, relOff := range relOffsets {
			addr, err := relOff.GetAddress(f.GetPointerAtAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to get swift protocol conformance address from relative indirectable pointer: %v", err)
			}

			if err := f.cr.SeekToAddr(addr); err != nil {
				return nil, fmt.Errorf("failed to seek to swift protocol conformance address %#x: %v", addr, err)
			}

			pcd, err := f.readProtocolConformance(f.cr, addr)
			if err != nil {
				return nil, fmt.Errorf("failed to read swift protocol conformance at address %#x: %w", addr, err)
			}
			protoConfDescs = append(protoConfDescs, *pcd)
		}

		return protoConfDescs, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_proto' section: %w", ErrSwiftSectionError)
}

// GetSwiftClosures parses all the closure context objects in the __TEXT.__swift5_capture section
func (f *File) GetSwiftClosures() (closures []swift.Capture, err error) {
	if sec := f.Section("__TEXT", "__swift5_capture"); sec != nil {
		f.cr.SeekToAddr(sec.Addr)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			off, _ := r.Seek(0, io.SeekCurrent)

			capture := swift.Capture{Address: sec.Addr + uint64(off)}

			if err := binary.Read(r, f.ByteOrder, &capture.CaptureDescriptor); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift %T: %w", capture.CaptureDescriptor, err)
			}

			if capture.NumCaptureTypes > 0 {
				capture.CaptureTypes = make([]swift.CaptureType, capture.NumCaptureTypes)
				for i := uint32(0); i < capture.NumCaptureTypes; i++ {
					curr, _ := r.Seek(0, io.SeekCurrent)
					if err := capture.CaptureTypes[i].CaptureTypeRecord.Read(r, capture.Address+uint64(curr-off)); err != nil {
						return nil, fmt.Errorf("failed to read swift %T: %v", capture.CaptureTypes[i].CaptureTypeRecord, err)
					}
				}
				for idx, ctype := range capture.CaptureTypes {
					capture.CaptureTypes[idx].TypeName, err = f.makeSymbolicMangledNameStringRef(ctype.MangledTypeName.GetAddress())
					if err != nil {
						return nil, fmt.Errorf("failed to read mangled type name at address %#x: %v", ctype.MangledTypeName.GetAddress(), err)
					}
				}
			}

			if capture.NumMetadataSources > 0 {
				capture.MetadataSources = make([]swift.MetadataSource, capture.NumMetadataSources)
				for i := uint32(0); i < capture.NumMetadataSources; i++ {
					curr, _ := r.Seek(0, io.SeekCurrent)
					if err := capture.MetadataSources[i].MetadataSourceRecord.Read(r, capture.Address+uint64(curr-off)); err != nil {
						return nil, fmt.Errorf("failed to read swift %T: %v", capture.MetadataSources[i].MetadataSourceRecord, err)
					}
				}
				for idx, msrc := range capture.MetadataSources {
					capture.MetadataSources[idx].MangledType, err = f.makeSymbolicMangledNameStringRef(msrc.MangledTypeNameOff.GetAddress())
					if err != nil {
						return nil, fmt.Errorf("failed to read mangled type name at address %#x: %v", msrc.MangledTypeNameOff.GetAddress(), err)
					}
					capture.MetadataSources[idx].MangledMetadataSource, err = f.makeSymbolicMangledNameStringRef(msrc.MangledMetadataSourceOff.GetAddress())
					if err != nil {
						return nil, fmt.Errorf("failed to read mangled metadata source at address %#x: %v", msrc.MangledMetadataSourceOff.GetAddress(), err)
					}
				}
			}

			if capture.NumBindings > 0 {
				capture.Bindings = make([]swift.NecessaryBindings, capture.NumBindings)
				for i := uint32(0); i < capture.NumBindings; i++ {
					curr, _ := r.Seek(0, io.SeekCurrent)
					if err := capture.Bindings[i].Read(r, capture.Address+uint64(curr-off)); err != nil {
						return nil, fmt.Errorf("failed to read swift %T: %v", capture.Bindings[i], err)
					}
				}
			}

			closures = append(closures, capture)
		}

		return closures, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_capture' section: %w", ErrSwiftSectionError)
}

// GetSwiftDynamicReplacementInfo parses the __TEXT.__swift5_replace section
func (f *File) GetSwiftDynamicReplacementInfo() (*swift.AutomaticDynamicReplacements, error) {
	if sec := f.Section("__TEXT", "__swift5_replace"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		var rep swift.AutomaticDynamicReplacements
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &rep); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", rep, err)
		}

		f.cr.Seek(int64(off)+int64(sizeOfInt32*2)+int64(rep.ReplacementScope), io.SeekStart)

		var rscope swift.DynamicReplacementScope
		if err := binary.Read(f.cr, f.ByteOrder, &rscope); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", rscope, err)
		}

		return &rep, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_replace' section: %w", ErrSwiftSectionError)
}

// GetSwiftDynamicReplacementInfoForOpaqueTypes parses the __TEXT.__swift5_replac2 section
func (f *File) GetSwiftDynamicReplacementInfoForOpaqueTypes() (*swift.AutomaticDynamicReplacementsSome, error) {
	if sec := f.Section("__TEXT", "__swift5_replac2"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		var rep2 swift.AutomaticDynamicReplacementsSome
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &rep2.Flags); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", rep2.Flags, err)
		}
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &rep2.NumReplacements); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", rep2.NumReplacements, err)
		}
		rep2.Replacements = make([]swift.DynamicReplacementSomeDescriptor, rep2.NumReplacements)
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &rep2.Replacements); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", rep2.Replacements, err)
		}

		return &rep2, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_replac2' section: %w", ErrSwiftSectionError)
}

// GetSwiftAccessibleFunctions parses the __TEXT.__swift5_acfuncs section
func (f *File) GetSwiftAccessibleFunctions() (funcs []swift.TargetAccessibleFunctionRecord, err error) {
	if sec := f.Section("__TEXT", "__swift5_acfuncs"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			curr, _ := r.Seek(0, io.SeekCurrent)
			var afr swift.TargetAccessibleFunctionRecord
			if err := afr.Read(r, sec.Addr+uint64(curr)); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift %T: %w", afr, err)
			}
			funcs = append(funcs, afr)
		}

		return funcs, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_acfuncs' section: %w", ErrSwiftSectionError)
}

// TODO: With the improvements to makeSymbolicMangledNameStringRef I believe I can NOW add this back in and add it to `PreCache()`
//// GetSwiftTypeRefs parses all the type references in the __TEXT.__swift5_typeref section
// func (f *File) GetSwiftTypeRefs() (trefs map[uint64]string, err error) {
// 	trefs = make(map[uint64]string)

// 	if sec := f.Section("__TEXT", "__swift5_typeref"); sec != nil {
// 		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
// 		}
// 		f.cr.Seek(int64(off), io.SeekStart)

// 		dat := make([]byte, sec.Size)
// 		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
// 			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
// 		}

// 		r := bytes.NewReader(dat)

// 		for {
// 			curr, _ := r.Seek(0, io.SeekCurrent)

// 			typ, err := f.makeSymbolicMangledNameStringRef(sec.Addr + uint64(curr))
// 			if err != nil {
// 				if errors.Is(err, io.EOF) {
// 					break
// 				}
// 				return nil, fmt.Errorf("failed to read swift AssociatedTypeDescriptor: %w", err)
// 			}

// 			trefs[sec.Addr+uint64(curr)] = typ
// 		}

// 		return trefs, nil
// 	}

// 	return nil, fmt.Errorf("MachO has no '__swift5_typeref' section: %w", ErrSwiftSectionError)
// }

// GetSwiftMultiPayloadEnums TODO: finish me
func (f *File) GetSwiftMultiPayloadEnums() (mpenums []swift.MultiPayloadEnum, err error) {
	if sec := f.Section("__TEXT", "__swift5_mpenum"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			curr, _ := r.Seek(0, io.SeekCurrent)

			var mpenum swift.MultiPayloadEnumDescriptor
			if err := binary.Read(r, f.ByteOrder, &mpenum.TypeName); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read %T: %w", mpenum, err)
			}

			var sizeFlags swift.MultiPayloadEnumSizeAndFlags
			if err := binary.Read(r, f.ByteOrder, &sizeFlags); err != nil {
				return nil, fmt.Errorf("failed to read %T: %w", sizeFlags, err)
			}

			if sizeFlags.UsesPayloadSpareBits() {
				var psbmask swift.MultiPayloadEnumPayloadSpareBitMaskByteCount
				if err := binary.Read(r, f.ByteOrder, &psbmask); err != nil {
					return nil, fmt.Errorf("failed to read %T: %w", psbmask, err)
				}
				r.Seek(-int64(binary.Size(sizeFlags)+binary.Size(psbmask)), io.SeekCurrent) // rewind
			} else {
				r.Seek(-int64(binary.Size(sizeFlags)), io.SeekCurrent) // rewind
			}

			mpenum.Contents = make([]uint32, sizeFlags.Size())
			// mpenumFlags = sizeFlags & 0xffff
			if err := binary.Read(r, f.ByteOrder, &mpenum.Contents); err != nil {
				return nil, fmt.Errorf("failed to read mpenum contents: %w", err)
			}

			// TODO: understand and use the large bit-mask

			addr := int64(sec.Addr) + int64(curr) + int64(mpenum.TypeName)
			name, err := f.makeSymbolicMangledNameStringRef(uint64(addr))
			if err != nil {
				return nil, fmt.Errorf("failed to read mangled type name @ %#x: %v", addr, err)
			}

			mpenums = append(mpenums, swift.MultiPayloadEnum{
				Address:  sec.Addr + uint64(curr),
				Type:     name,
				Contents: mpenum.Contents,
			})
		}

		return mpenums, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_mpenum' section: %w", ErrSwiftSectionError)
}

// GetSwiftColocateTypeDescriptors parses all the colocated type descriptors in the __TEXT.__constg_swiftt section
func (f *File) GetSwiftColocateTypeDescriptors() ([]swift.Type, error) {
	if sec := f.Section("__TEXT", "__constg_swiftt"); sec != nil {
		var typs []swift.Type

		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %w", err)
		}

		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %w", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			curr, _ := r.Seek(0, io.SeekCurrent)

			typ, err := f.readType(r, sec.Addr+uint64(curr))
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift colocate type at address %#x: %w", sec.Addr+uint64(curr), err)
			}

			typs = append(typs, *typ)
		}

		return typs, nil
	}

	return nil, fmt.Errorf("MachO has no '__constg_swiftt' section: %w", ErrSwiftSectionError)
}

// GetSwiftColocateMetadata parses all the colocated metadata in the __TEXT.__textg_swiftm section
func (f *File) GetSwiftColocateMetadata() ([]swift.ConformanceDescriptor, error) {
	if sec := f.Section("__TEXT", "__textg_swiftm"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)
		panic("not implimented") // FIXME: finish me (I can't find any examples of this section in the wild)
	}
	return nil, fmt.Errorf("MachO has no '__textg_swiftm' section: %w", ErrSwiftSectionError)
}

// GetSwiftTypes parses all the swift in the __TEXT.__swift5_types section
func (f *File) GetSwiftTypes() (typs []swift.Type, err error) {
	for _, sec := range f.Sections {
		if sec.Seg == "__TEXT" && (sec.Name == "__swift5_types" || sec.Name == "__swift5_types2") {
			off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
			if err != nil {
				return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
			}
			f.cr.Seek(int64(off), io.SeekStart)

			dat := make([]byte, sec.Size)
			if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
				return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
			}

			r := bytes.NewReader(dat)

			relOffsets := make([]swift.RelativeIndirectablePointer, len(dat)/sizeOfInt32)
			for i := 0; i < len(dat)/sizeOfInt32; i++ {
				curr, _ := r.Seek(0, io.SeekCurrent)
				relOffsets[i].Address = sec.Addr + uint64(curr)
				if err := binary.Read(r, f.ByteOrder, &relOffsets[i].RelOff); err != nil {
					return nil, fmt.Errorf("failed to read relative offsets: %v", err)
				}
			}

			for _, relOff := range relOffsets {
				addr, err := relOff.GetAddress(f.GetPointerAtAddress)
				if err != nil {
					return nil, fmt.Errorf("failed to get type address from relative indirectable pointer: %v", err)
				}

				if typ, ok := f.swift[addr]; ok { // check cache
					if typ, ok := typ.(*swift.Type); ok {
						typs = append(typs, *typ)
					}
				} else {
					if err := f.cr.SeekToAddr(addr); err != nil {
						return nil, fmt.Errorf("failed to seek to swift type address %#x: %v", addr, err)
					}

					typ, err := f.readType(f.cr, addr)
					if err != nil {
						return nil, fmt.Errorf("failed to read type at address %#x: %v", addr, err)
					}

					typs = append(typs, *typ)
				}
			}
		}
	}

	if len(typs) > 0 {
		return typs, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_types' or '__swift5_types2' sections: %w", ErrSwiftSectionError)
}

func (f *File) readType(r io.ReadSeeker, addr uint64) (typ *swift.Type, err error) {
	var desc swift.TargetContextDescriptor
	if err := desc.Read(r, addr); err != nil {
		return nil, fmt.Errorf("failed to read swift type context descriptor: %w", err)
	}
	r.Seek(-desc.Size(), io.SeekCurrent) // rewind

	typ = &swift.Type{Address: addr, Kind: desc.Flags.Kind()}

	switch desc.Flags.Kind() {
	case swift.CDKindModule:
		if err := f.parseModule(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s flags(%s): %w", typ.Kind, desc.Flags, err)
		}
	case swift.CDKindExtension:
		if err := f.parseExtension(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s flags(%s): %w", typ.Kind, desc.Flags, err)
		}
	case swift.CDKindAnonymous:
		if err := f.parseAnonymous(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s flags(%s): %w", typ.Kind, desc.Flags, err)
		}
	case swift.CDKindProtocol:
		if _, err := f.parseProtocol(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s flags(%s): %w", typ.Kind, desc.Flags, err)
		}
	case swift.CDKindOpaqueType:
		if err := f.parseOpaqueType(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s flags(%s): %w", typ.Kind, desc.Flags, err)
		}
	case swift.CDKindClass:
		if err := f.parseClassDescriptor(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s flags(%s): %w", typ.Kind, desc.Flags, err)
		}
	case swift.CDKindStruct:
		if err := f.parseStructDescriptor(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s flags(%s): %w", typ.Kind, desc.Flags, err)
		}
	case swift.CDKindEnum:
		if err := f.parseEnumDescriptor(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s flags(%s): %w", typ.Kind, desc.Flags, err)
		}
	default:
		return nil, fmt.Errorf("unknown swift type kind: %v flags(%s)", desc.Flags.Kind(), desc.Flags)
	}

	f.swift[typ.Address] = typ // cache type

	return typ, nil
}

/***************
* TYPE PARSERS *
****************/

func (f *File) parseModule(r io.Reader, typ *swift.Type) (err error) {
	var mod swift.TargetModuleContextDescriptor
	if err := mod.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read swift module descriptor: %v", err)
	}

	typ.Name, err = f.GetCString(mod.NameOffset.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read type name: %v", err)
	}

	if mod.ParentOffset.IsSet() {
		f.cr.SeekToAddr(mod.ParentOffset.GetAddress())
		ctx, err := f.getContextDesc(mod.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent = &swift.Type{
			Address: mod.ParentOffset.GetAddress(),
			Name:    ctx.Name,
			Parent: &swift.Type{
				Name: ctx.Parent,
			},
		}
	}

	typ.Type = mod
	typ.Size = mod.Size()

	return nil
}

func (f *File) parseExtension(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var ext swift.Extension
	if err := ext.TargetExtensionContextDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read swift module descriptor: %v", err)
	}

	if ext.Flags.IsGeneric() {
		ext.GenericContext = &swift.GenericContext{}
		if err := binary.Read(r, f.ByteOrder, &ext.GenericContext.TargetGenericContextDescriptorHeader); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		ext.GenericContext.Parameters = make([]swift.GenericParamDescriptor, ext.GenericContext.NumParams)
		if err := binary.Read(r, f.ByteOrder, &ext.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
		curr, _ := r.Seek(0, io.SeekCurrent)
		r.Seek(int64(Align(uint64(curr), 4)), io.SeekStart)
		ext.GenericContext.Requirements = make([]swift.TargetGenericRequirementDescriptor, ext.GenericContext.NumRequirements)
		for i := 0; i < int(ext.GenericContext.NumRequirements); i++ {
			curr, _ = r.Seek(0, io.SeekCurrent)
			if err := ext.GenericContext.Requirements[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read generic requirement: %v", err)
			}
		}
		// ext.GenericContext.KeyArguments = make([]swift.GenericPackShapeDescriptor, ext.GenericContext.NumKeyArguments)
		// if err := binary.Read(r, f.ByteOrder, &ext.GenericContext.KeyArguments); err != nil {
		// 	return fmt.Errorf("failed to read generic key arguments: %v", err)
		// }
	}

	if ext.ParentOffset.IsSet() {
		f.cr.SeekToAddr(ext.ParentOffset.GetAddress())
		ctx, err := f.getContextDesc(ext.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent = &swift.Type{
			Address: ext.ParentOffset.GetAddress(),
			Name:    ctx.Name,
			Parent: &swift.Type{
				Name: ctx.Parent,
			},
		}
	}

	typ.Name, err = f.makeSymbolicMangledNameStringRef(ext.ExtendedContext.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read extended context: %v", err)
	}

	curr, _ := r.Seek(0, io.SeekCurrent)
	typ.Size = int64(curr - off)
	typ.Type = &ext

	return nil
}

func (f *File) parseAnonymous(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var anon swift.Anonymous
	if err := anon.TargetAnonymousContextDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read swift anonymous descriptor: %v", err)
	}

	if anon.Flags.IsGeneric() {
		anon.GenericContext = &swift.GenericContext{}
		if err := binary.Read(r, f.ByteOrder, &anon.GenericContext.TargetGenericContextDescriptorHeader); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		anon.GenericContext.Parameters = make([]swift.GenericParamDescriptor, anon.GenericContext.NumParams)
		if err := binary.Read(r, f.ByteOrder, &anon.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
		curr, _ := r.Seek(0, io.SeekCurrent)
		r.Seek(int64(Align(uint64(curr), 4)), io.SeekStart)
		anon.GenericContext.Requirements = make([]swift.TargetGenericRequirementDescriptor, anon.GenericContext.NumRequirements)
		for i := 0; i < int(anon.GenericContext.NumRequirements); i++ {
			curr, _ = r.Seek(0, io.SeekCurrent)
			if err := anon.GenericContext.Requirements[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read generic requirement: %v", err)
			}
		}
		// args := make([]swift.GenericPackShapeDescriptor, g.Base.NumKeyArguments)
		// if err := binary.Read(r, f.ByteOrder, &args); err != nil {
		// 	return fmt.Errorf("failed to read generic key arguments: %v", err)
		// }
		// _ = args // TODO: use this
	}

	if anon.HasMangledName() {
		curr, _ := r.Seek(0, io.SeekCurrent)
		var name swift.TargetMangledContextName
		if err := name.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read mangled name: %v", err)
		}
		anon.MangledContextName, err = f.GetCString(name.Name.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to read cstring: %v", err)
		}
		typ.Name = anon.MangledContextName
	}

	if anon.ParentOffset.IsSet() {
		f.cr.SeekToAddr(anon.ParentOffset.GetAddress())
		ctx, err := f.getContextDesc(anon.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent = &swift.Type{
			Address: anon.ParentOffset.GetAddress(),
			Name:    ctx.Name,
			Parent: &swift.Type{
				Name: ctx.Parent,
			},
		}
	}

	curr, _ := r.Seek(0, io.SeekCurrent)
	typ.Size = int64(curr - off)
	typ.Type = anon

	return nil
}

func (f *File) parseProtocol(r io.ReadSeeker, typ *swift.Type) (prot *swift.Protocol, err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	prot = &swift.Protocol{Address: typ.Address}

	if err := prot.TargetProtocolDescriptor.Read(r, typ.Address); err != nil {
		return nil, fmt.Errorf("failed to read swift module descriptor: %v", err)
	}

	if prot.NumRequirementsInSignature > 0 {
		prot.SignatureRequirements = make([]swift.TargetGenericRequirement, prot.NumRequirementsInSignature)
		for i := 0; i < int(prot.NumRequirementsInSignature); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := prot.SignatureRequirements[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return nil, fmt.Errorf("failed to read protocols signature requirements : %v", err)
			}
		}
	}

	if prot.NumRequirements > 0 {
		prot.Requirements = make([]swift.TargetProtocolRequirement, prot.NumRequirements)
		for i := 0; i < int(prot.NumRequirements); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := prot.Requirements[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return nil, fmt.Errorf("failed to read protocols requirements : %v", err)
			}
		}
	}

	if prot.ParentOffset.IsSet() {
		f.cr.SeekToAddr(prot.ParentOffset.GetAddress())
		prot.Parent, err = f.getContextDesc(prot.ParentOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent = &swift.Type{
			Address: prot.ParentOffset.GetAddress(),
			Name:    prot.Parent.Name,
			Parent: &swift.Type{
				Name: prot.Parent.Parent,
			},
		}
	}

	prot.Name, err = f.GetCString(prot.NameOffset.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}
	typ.Name = prot.Name

	if prot.AssociatedTypeNamesOffset.IsSet() {
		prot.AssociatedTypes, err = f.getAssociatedTypes(prot.AssociatedTypeNamesOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to get associated types: %v", err)
		}
	}

	curr, _ := r.Seek(0, io.SeekCurrent)
	typ.Size = int64(curr - off)
	typ.Type = *prot

	return prot, nil
}

func (f *File) readProtocolConformance(r io.ReadSeeker, addr uint64) (pcd *swift.ConformanceDescriptor, err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	pcd = &swift.ConformanceDescriptor{Address: addr}

	if err := pcd.TargetProtocolConformanceDescriptor.Read(f.cr, pcd.Address); err != nil {
		return nil, fmt.Errorf("failed to read swift TargetProtocolConformanceDescriptor: %v", err)
	}

	if pcd.Flags.IsRetroactive() {
		curr, _ := r.Seek(0, io.SeekCurrent)
		pcd.Retroactive = &swift.RelativeString{}
		pcd.Retroactive.Address = pcd.Address + uint64(curr-off)
		if err := binary.Read(r, f.ByteOrder, &pcd.Retroactive.RelOff); err != nil {
			return nil, fmt.Errorf("failed to read retroactive conformance descriptor header: %v", err)
		}
	}

	if pcd.Flags.GetNumConditionalRequirements() > 0 {
		pcd.ConditionalRequirements = make([]swift.TargetGenericRequirement, pcd.Flags.GetNumConditionalRequirements())
		for i := 0; i < pcd.Flags.GetNumConditionalRequirements(); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := pcd.ConditionalRequirements[i].Read(r, pcd.Address+uint64(curr-off)); err != nil {
				return nil, fmt.Errorf("failed to read conditional requirement: %v", err)
			}
		}
	}

	if pcd.Flags.NumConditionalPackShapeDescriptors() > 0 {
		var hdr swift.GenericPackShapeHeader
		if err := binary.Read(r, f.ByteOrder, &hdr); err != nil {
			return nil, fmt.Errorf("failed to read conditional pack shape header: %v", err)
		}
		_ = hdr // TODO: use this
		pcd.ConditionalPackShapes = make([]swift.GenericPackShapeDescriptor, pcd.Flags.NumConditionalPackShapeDescriptors())
		if err := binary.Read(r, f.ByteOrder, &pcd.ConditionalPackShapes); err != nil {
			return nil, fmt.Errorf("failed to read conditional pack shape descriptors: %v", err)
		}
	}

	if pcd.Flags.HasResilientWitnesses() {
		var rwit swift.TargetResilientWitnessesHeader
		if err := binary.Read(r, f.ByteOrder, &rwit); err != nil {
			return nil, fmt.Errorf("failed to read resilient witnesses offset: %v", err)
		}
		pcd.ResilientWitnesses = make([]swift.ResilientWitnesses, rwit.NumWitnesses)
		for i := 0; i < int(rwit.NumWitnesses); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent) // save offset
			if err := pcd.ResilientWitnesses[i].Read(r, pcd.Address+uint64(curr-off)); err != nil {
				return nil, fmt.Errorf("failed to read protocols requirements : %v", err)
			}
		}
	}

	if pcd.Flags.HasGenericWitnessTable() {
		pcd.GenericWitnessTable = &swift.TargetGenericWitnessTable{}
		if err := binary.Read(r, f.ByteOrder, pcd.GenericWitnessTable); err != nil {
			return nil, fmt.Errorf("failed to read generic witness table: %v", err)
		}
	}

	paddr, err := pcd.ProtocolOffsest.GetAddress(f.GetPointerAtAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to read protocol offset pointer flags(%s): %v", pcd.Flags.String(), err)
	}
	if paddr == 0 {
		pcd.Protocol, err = f.GetBindName(paddr)
		if err != nil {
			pcd.Protocol = "<stripped>"
		}
	} else {
		ctx, err := f.getContextDesc(pcd.ProtocolOffsest.GetRelPtrAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read protocol name: %v", err)
		}
		pcd.Protocol = ctx.Name
	}

	// parse type reference
	switch pcd.Flags.GetTypeReferenceKind() {
	case swift.DirectTypeDescriptor:
		f.cr.SeekToAddr(pcd.TypeRefOffsest.GetRelPtrAddress())
		pcd.TypeRef, err = f.readType(f.cr, pcd.TypeRefOffsest.GetRelPtrAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read type: %v", err)
		}
	case swift.IndirectTypeDescriptor:
		addr, err := pcd.TypeRefOffsest.GetAddress(f.GetPointerAtAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to get indirect type descriptor address: %v", err)
		}
		ptr, err := f.GetPointerAtAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to get indirect type descriptor pointer: %v", err)
		}
		ptr = f.vma.Convert(ptr)
		if ptr == 0 {
			bind, err := f.GetBindName(addr)
			if err == nil {
				pcd.TypeRef = &swift.Type{
					Address: ptr,
					Name:    bind,
				}
			}
		} else {
			f.cr.SeekToAddr(ptr)
			ctx, err := f.getContextDesc(ptr)
			if err != nil {
				return nil, fmt.Errorf("failed to get parent: %v", err)
			}
			pcd.TypeRef = &swift.Type{
				Address: ptr,
				Name:    ctx.Name,
				Parent: &swift.Type{
					Name: ctx.Parent,
				},
			}

		}
	case swift.DirectObjCClassName:
		name, err := f.GetCString(pcd.TypeRefOffsest.GetRelPtrAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift objc class name: %v", err)
		}
		pcd.TypeRef = &swift.Type{
			Address: pcd.TypeRefOffsest.GetRelPtrAddress(),
			Name:    name,
			Kind:    swift.CDKindClass,
			Parent:  nil,
		}
	case swift.IndirectObjCClass:
		addr, err := pcd.TypeRefOffsest.GetAddress(f.GetPointerAtAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to get indirect type descriptor address: %v", err)
		}
		ptr, err := f.GetPointerAtAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to get indirect type descriptor pointer: %v", err)
		}
		ptr = f.vma.Convert(ptr)
		name, err := f.GetCString(ptr)
		if err != nil {
			return nil, fmt.Errorf("failed to read swift indirect objc class name : %v", err)
		}
		pcd.TypeRef = &swift.Type{
			Address: ptr,
			Name:    name,
			Kind:    swift.CDKindClass,
			Parent:  nil,
		}
	}

	for idx, wit := range pcd.ResilientWitnesses {
		addr, err := wit.RequirementOff.GetAddress(f.GetPointerAtAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to read resilient witness requirement address: %v", err)
		}
		if addr == 0 {
			pcd.ResilientWitnesses[idx].Symbol = "<stripped>"
		} else {
			if bind, err := f.GetBindName(addr); err == nil {
				pcd.ResilientWitnesses[idx].Symbol = bind
			} else if syms, err := f.FindAddressSymbols(addr); err == nil {
				if len(syms) > 0 {
					for _, s := range syms {
						if !s.Type.IsDebugSym() {
							pcd.ResilientWitnesses[idx].Symbol = s.Name
							break
						}
					}
				}
			} else {
				if err := f.cr.SeekToAddr(addr); err != nil {
					return nil, fmt.Errorf("failed to seek to resilient witness requirement address: %v", err)
				}
				if err := pcd.ResilientWitnesses[idx].Requirement.Read(f.cr, addr); err != nil {
					return nil, fmt.Errorf("failed to read target protocol requirement: %v", err)
				}
				if wit.ImplOff.IsSet() {
					if syms, err := f.FindAddressSymbols(wit.ImplOff.GetAddress()); err == nil {
						if len(syms) > 0 {
							for _, s := range syms {
								if !s.Type.IsDebugSym() {
									pcd.ResilientWitnesses[idx].Symbol = s.Name
									break
								}
							}
						}
					}
				}
			}
		}
	}

	if pcd.WitnessTablePatternOffsest.IsSet() {
		ptr, err := f.GetPointerAtAddress(pcd.WitnessTablePatternOffsest.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read witness table pattern address pointer: %v", err)
		}
		var wtpname string
		if ptr != pcd.Address && ptr+f.preferredLoadAddress() != pcd.Address {
			ctx, err := f.getContextDesc(ptr)
			if err != nil {
				return nil, fmt.Errorf("failed to read witness table pattern name: %v", err)
			}
			wtpname = ctx.Name
			// f.cr.SeekToAddr(pcd.WitnessTablePatternOffsest.GetAddress())
			// wtpname, err := f.readType(f.cr, pcd.WitnessTablePatternOffsest.GetAddress())
			// if err != nil {
			// 	return nil, fmt.Errorf("failed to read witness table pattern name: %v", err)
			// }
		}
		pcd.WitnessTablePattern = &swift.PCDWitnessTable{
			Address: pcd.WitnessTablePatternOffsest.GetAddress(),
			Name:    wtpname,
		}
	}

	if pcd.Retroactive != nil {
		ctx, err := f.getContextDesc(pcd.Retroactive.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read retroactive name: %v", err)
		}
		pcd.Retroactive.Name = ctx.Name
	}

	return pcd, nil
}

func (f *File) parseOpaqueType(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var ot swift.OpaqueType
	if err := ot.TargetContextDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read swift opaque type descriptor: %v", err)
	}

	if ot.Flags.IsGeneric() {
		ot.GenericContext = &swift.GenericContext{}
		if err := binary.Read(r, f.ByteOrder, &ot.GenericContext.TargetGenericContextDescriptorHeader); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		ot.GenericContext.Parameters = make([]swift.GenericParamDescriptor, ot.GenericContext.NumParams)
		if err := binary.Read(r, f.ByteOrder, &ot.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
		curr, _ := r.Seek(0, io.SeekCurrent)
		r.Seek(int64(Align(uint64(curr), 4)), io.SeekStart)
		ot.GenericContext.Requirements = make([]swift.TargetGenericRequirementDescriptor, ot.GenericContext.NumRequirements)
		for i := 0; i < int(ot.GenericContext.NumRequirements); i++ {
			curr, _ = r.Seek(0, io.SeekCurrent)
			if err := ot.GenericContext.Requirements[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read generic requirement: %v", err)
			}
		}
	}

	if uint32(ot.Flags.KindSpecific()) > 0 { // TypeArgs
		for i := 0; i < int(ot.Flags.KindSpecific()); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			var reloff int32
			if err := binary.Read(r, f.ByteOrder, &reloff); err != nil {
				return fmt.Errorf("failed to read type arg relative offset: %v", err)
			}
			ot.TypeArgs = append(ot.TypeArgs, swift.RelativeString{
				RelativeDirectPointer: swift.RelativeDirectPointer{
					Address: typ.Address + uint64(curr-off),
					RelOff:  reloff,
				},
				Name: "",
			})
		}
		for idx, targ := range ot.TypeArgs {
			ot.TypeArgs[idx].Name, err = f.makeSymbolicMangledNameStringRef(targ.GetAddress())
			if err != nil {
				return fmt.Errorf("failed to read type arg name: %v", err)
			}
		}
	}

	if ot.ParentOffset.IsSet() {
		f.cr.SeekToAddr(ot.ParentOffset.GetAddress())
		ctx, err := f.getContextDesc(ot.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent = &swift.Type{
			Address: ot.ParentOffset.GetAddress(),
			Name:    ctx.Name,
			Parent: &swift.Type{
				Name: ctx.Parent,
			},
		}
	}

	curr, _ := r.Seek(0, io.SeekCurrent)
	typ.Size = int64(curr - off)
	typ.Type = ot

	return nil
}

func (f *File) parseClassDescriptor(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var class swift.Class
	if err := class.TargetClassDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read %T: %v", class.TargetClassDescriptor, err)
	}

	if class.Flags.IsGeneric() {
		class.GenericContext = &swift.TypeGenericContext{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := class.GenericContext.TargetTypeGenericContextDescriptorHeader.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		class.GenericContext.Parameters = make([]swift.GenericParamDescriptor, class.GenericContext.Base.NumParams)
		if err := binary.Read(r, f.ByteOrder, &class.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
		curr, _ = r.Seek(0, io.SeekCurrent)
		r.Seek(int64(Align(uint64(curr), 4)), io.SeekStart)
		class.GenericContext.Requirements = make([]swift.TargetGenericRequirementDescriptor, class.GenericContext.Base.NumRequirements)
		for i := 0; i < int(class.GenericContext.Base.NumRequirements); i++ {
			curr, _ = r.Seek(0, io.SeekCurrent)
			if err := class.GenericContext.Requirements[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read generic requirement: %v", err)
			}
		}
		// args := make([]swift.GenericPackShapeDescriptor, g.Base.NumKeyArguments)
		// if err := binary.Read(r, f.ByteOrder, &args); err != nil {
		// 	return fmt.Errorf("failed to read generic key arguments: %v", err)
		// }
		// _ = args // TODO: use this
	}

	if class.Flags.KindSpecific().HasResilientSuperclass() {
		curr, _ := r.Seek(0, io.SeekCurrent)
		class.ResilientSuperclass = &swift.ResilientSuperclass{}
		if err := class.ResilientSuperclass.TargetResilientSuperclass.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read resilient superclass: %v", err)
		}
	}

	if class.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
		class.ForeignMetadata = &swift.TargetForeignMetadataInitialization{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := class.ForeignMetadata.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read foreign metadata initialization: %v", err)
		}
	}

	if class.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
		class.SingletonMetadata = &swift.TargetSingletonMetadataInitialization{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := class.SingletonMetadata.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read singleton metadata initialization: %v", err)
		}
	}

	if class.Flags.KindSpecific().HasVTable() {
		class.VTable = &swift.VTable{}
		if err := binary.Read(r, f.ByteOrder, &class.VTable.TargetVTableDescriptorHeader); err != nil {
			return fmt.Errorf("failed to read vtable header: %v", err)
		}
		class.VTable.Methods = make([]swift.Method, class.VTable.VTableSize)
		for i := 0; i < int(class.VTable.VTableSize); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := class.VTable.Methods[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read vtable method descriptor: %v", err)
			}
		}
	}

	if class.Flags.KindSpecific().HasOverrideTable() {
		var ohdr swift.TargetOverrideTableHeader
		if err := binary.Read(r, f.ByteOrder, &ohdr); err != nil {
			return fmt.Errorf("failed to read method override table header: %v", err)
		}
		class.MethodOverrides = make([]swift.TargetMethodOverrideDescriptor, ohdr.NumEntries)
		for i := uint32(0); i < ohdr.NumEntries; i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := class.MethodOverrides[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read method override table entry: %v", err)
			}
		}
	}

	if class.HasObjCResilientClassStub() {
		curr, _ := r.Seek(0, io.SeekCurrent)
		class.ObjCResilientClassStubInfo = &swift.TargetObjCResilientClassStubInfo{}
		if err := class.ObjCResilientClassStubInfo.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read objc resilient class stub: %v", err)
		}
	}

	if class.Flags.KindSpecific().HasCanonicalMetadataPrespecializations() {
		var lc swift.TargetCanonicalSpecializedMetadatasListCount
		if err := binary.Read(r, f.ByteOrder, &lc); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		class.Metadatas = make([]swift.Metadata, lc.Count)
		for i := 0; i < int(lc.Count); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := class.Metadatas[i].TargetCanonicalSpecializedMetadatasListEntry.Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read canonical metadata list entry: %v", err)
			}
		}
		class.CachingOnceToken = &swift.TargetCanonicalSpecializedMetadatasCachingOnceToken{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := class.CachingOnceToken.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		class.MetadataAccessors = make([]swift.TargetCanonicalSpecializedMetadataAccessorsListEntry, lc.Count)
		for i := 0; i < int(lc.Count); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := class.MetadataAccessors[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read canonical metadata accessors list entry: %v", err)
			}
		}
		for idx, m := range class.Metadatas {
			f.cr.SeekToAddr(m.Metadata.GetAddress())
			if err := binary.Read(f.cr, f.ByteOrder, &class.Metadatas[idx].TargetMetadata); err != nil {
				return fmt.Errorf("failed to read metadata: %w", err)
			}
			class.Metadatas[idx].TargetMetadata.TypeDescriptor = f.vma.Convert(class.Metadatas[idx].TargetMetadata.TypeDescriptor)
			class.Metadatas[idx].TargetMetadata.TypeMetadataAddress = f.vma.Convert(class.Metadatas[idx].TargetMetadata.TypeMetadataAddress)
		}
	}

	if class.FieldOffsetVectorOffset != 0 {
		if class.Flags.KindSpecific().HasResilientSuperclass() {
			class.FieldOffsetVectorOffset += class.MetadataNegativeSizeInWordsORResilientMetadataBounds
		}
		// FIXME: what the hell are field offset vectors?
	}

	if class.ResilientSuperclass != nil {
		addr, err := class.ResilientSuperclass.Superclass.GetAddress(f.cr)
		if err != nil {
			return fmt.Errorf("failed to read superclass address: %v", err)
		}
		_ = addr // TODO: use this
		// class.ResilientSuperclass.Name, err = f.??(addr)
		// if err != nil {
		// 	return fmt.Errorf("failed to read swift class resilient superclass mangled name: %v", err)
		// }
	}

	if class.SuperclassType.IsSet() {
		class.SuperClass, err = f.makeSymbolicMangledNameStringRef(class.SuperclassType.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to read swift class superclass mangled name: %v", err)
		}
	}

	typ.Name, err = f.GetCString(class.NameOffset.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read cstring: %v", err)
	}

	if class.ParentOffset.IsSet() {
		f.cr.SeekToAddr(class.ParentOffset.GetAddress())
		ctx, err := f.getContextDesc(class.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent = &swift.Type{
			Address: class.ParentOffset.GetAddress(),
			Name:    ctx.Name,
			Parent: &swift.Type{
				Name: ctx.Parent,
			},
		}
	}

	if class.FieldsOffset.IsSet() {
		if item, ok := f.swift[class.FieldsOffset.GetAddress()]; ok { // check cache
			if fd, ok := item.(*swift.Field); ok {
				typ.Fields = fd
			}
		} else {
			f.cr.SeekToAddr(class.FieldsOffset.GetAddress())
			fd, err := f.readField(f.cr, class.FieldsOffset.GetAddress())
			if err != nil {
				return fmt.Errorf("failed to read swift field: %w", err)
			}
			typ.Fields = fd
		}
	}

	if class.VTable != nil { // enrich vtable
		for idx, method := range class.VTable.Methods {
			// set address
			if method.Flags.IsAsync() {
				f.cr.SeekToAddr(method.Impl.GetRelPtrAddress())
				class.VTable.Methods[idx].Address, err = method.Impl.GetAddress(f.cr)
				if err != nil {
					return fmt.Errorf("failed to read targer relative direct pointer: %v", err)
				}
			} else {
				class.VTable.Methods[idx].Address = method.Impl.GetRelPtrAddress()
			}
			// set symbol
			if syms, err := f.FindAddressSymbols(class.VTable.Methods[idx].Address); err == nil {
				if len(syms) > 0 {
					for _, s := range syms {
						if !s.Type.IsDebugSym() {
							class.VTable.Methods[idx].Symbol = s.Name
							break
						}
					}
				}
			}
		}
		// collect vars
		var vars []swift.FieldRecord
		for _, f := range typ.Fields.Records {
			if f.Flags.IsVar() {
				vars = append(vars, f)
			}
		}
		// map vars to getter/setter/modify methods
		if len(vars) > 0 && len(vars)*3 <= len(class.VTable.Methods) {
			fidx := 0
			prev := swift.MDKMax
			var mindexes []int
			for idx, method := range class.VTable.Methods {
				switch method.Flags.Kind() {
				case swift.MDKGetter:
					if prev == swift.MDKMax {
						mindexes = append(mindexes, idx)
					} else {
						prev = swift.MDKMax
						mindexes = []int{}
						mindexes = append(mindexes, idx)
					}
				case swift.MDKSetter:
					if prev == swift.MDKGetter {
						mindexes = append(mindexes, idx)
					} else {
						prev = swift.MDKMax
						mindexes = []int{}
					}
				case swift.MDKModifyCoroutine:
					if prev == swift.MDKSetter {
						mindexes = append(mindexes, idx)
						for _, m := range mindexes {
							if fidx < len(vars) {
								if class.VTable.Methods[m].Symbol == "" {
									if class.VTable.Methods[m].Impl.IsSet() {
										class.VTable.Methods[m].Symbol = fmt.Sprintf("%s.%s.sub_%x", strings.TrimPrefix(vars[fidx].Name, "$__lazy_storage_$_"), class.VTable.Methods[m].Flags.Kind(), class.VTable.Methods[m].Address)
									} else {
										class.VTable.Methods[m].Symbol = fmt.Sprintf("%s.%s", strings.TrimPrefix(vars[fidx].Name, "$__lazy_storage_$_"), class.VTable.Methods[m].Flags.Kind())
									}
								}
							}
						}
						fidx++
					} else {
						prev = swift.MDKMax
						mindexes = []int{}
					}
				}
				prev = method.Flags.Kind()
			}
		}
	}

	curr, _ := r.Seek(0, io.SeekCurrent)
	typ.Size = int64(curr - off)
	typ.Type = class

	return nil
}

func (f *File) parseStructDescriptor(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var st swift.Struct
	if err := st.TargetStructDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read %T: %v", st.TargetStructDescriptor, err)
	}

	if st.Flags.IsGeneric() {
		st.GenericContext = &swift.TypeGenericContext{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := st.GenericContext.TargetTypeGenericContextDescriptorHeader.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		st.GenericContext.Parameters = make([]swift.GenericParamDescriptor, st.GenericContext.Base.NumParams)
		if err := binary.Read(r, f.ByteOrder, &st.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
		curr, _ = r.Seek(0, io.SeekCurrent)
		r.Seek(int64(Align(uint64(curr), 4)), io.SeekStart)
		st.GenericContext.Requirements = make([]swift.TargetGenericRequirementDescriptor, st.GenericContext.Base.NumRequirements)
		for i := 0; i < int(st.GenericContext.Base.NumRequirements); i++ {
			curr, _ = r.Seek(0, io.SeekCurrent)
			if err := st.GenericContext.Requirements[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read generic requirement: %v", err)
			}
		}
		// args := make([]swift.GenericPackShapeDescriptor, g.Base.NumKeyArguments)
		// if err := binary.Read(r, f.ByteOrder, &args); err != nil {
		// 	return fmt.Errorf("failed to read generic key arguments: %v", err)
		// }
		// _ = args // TODO: use this
	}

	if st.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
		st.ForeignMetadata = &swift.TargetForeignMetadataInitialization{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := st.ForeignMetadata.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read foreign metadata initialization: %v", err)
		}
	}

	if st.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
		st.SingletonMetadata = &swift.TargetSingletonMetadataInitialization{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := st.SingletonMetadata.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read singleton metadata initialization: %v", err)
		}
	}

	if st.Flags.KindSpecific().HasCanonicalMetadataPrespecializations() {
		var lc swift.TargetCanonicalSpecializedMetadatasListCount
		if err := binary.Read(r, f.ByteOrder, &lc); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		st.Metadatas = make([]swift.Metadata, lc.Count)
		for i := 0; i < int(lc.Count); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := st.Metadatas[i].TargetCanonicalSpecializedMetadatasListEntry.Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read canonical metadata list entry: %v", err)
			}
		}
		st.CachingOnceToken = &swift.TargetCanonicalSpecializedMetadatasCachingOnceToken{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := st.CachingOnceToken.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		for idx, m := range st.Metadatas {
			f.cr.SeekToAddr(m.Metadata.GetAddress())
			if err := binary.Read(f.cr, f.ByteOrder, &st.Metadatas[idx].TargetMetadata); err != nil {
				return fmt.Errorf("failed to read metadata: %w", err)
			}
			st.Metadatas[idx].TargetMetadata.TypeDescriptor = f.vma.Convert(st.Metadatas[idx].TargetMetadata.TypeDescriptor)
			st.Metadatas[idx].TargetMetadata.TypeMetadataAddress = f.vma.Convert(st.Metadatas[idx].TargetMetadata.TypeMetadataAddress)
		}
	}

	typ.Name, err = f.GetCString(st.NameOffset.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read cstring: %v", err)
	}

	if st.ParentOffset.IsSet() {
		f.cr.SeekToAddr(st.ParentOffset.GetAddress())
		ctx, err := f.getContextDesc(st.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent = &swift.Type{
			Address: st.ParentOffset.GetAddress(),
			Name:    ctx.Name,
			Parent: &swift.Type{
				Name: ctx.Parent,
			},
		}
	}

	if st.FieldsOffset.IsSet() {
		if item, ok := f.swift[st.FieldsOffset.GetAddress()]; ok { // check cache
			if fd, ok := item.(*swift.Field); ok {
				typ.Fields = fd
			}
		} else {
			f.cr.SeekToAddr(st.FieldsOffset.GetAddress())
			fd, err := f.readField(f.cr, st.FieldsOffset.GetAddress())
			if err != nil {
				return fmt.Errorf("failed to read swift field: %w", err)
			}
			typ.Fields = fd
		}
	}

	curr, _ := r.Seek(0, io.SeekCurrent)
	typ.Size = int64(curr - off)
	typ.Type = st

	return nil
}

func (f *File) parseEnumDescriptor(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var enum swift.Enum
	if err := enum.TargetEnumDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read %T: %v", enum.TargetEnumDescriptor, err)
	}

	if enum.Flags.IsGeneric() {
		enum.GenericContext = &swift.TypeGenericContext{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := enum.GenericContext.TargetTypeGenericContextDescriptorHeader.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		enum.GenericContext.Parameters = make([]swift.GenericParamDescriptor, enum.GenericContext.Base.NumParams)
		if err := binary.Read(r, f.ByteOrder, &enum.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
		curr, _ = r.Seek(0, io.SeekCurrent)
		r.Seek(int64(Align(uint64(curr), 4)), io.SeekStart)
		enum.GenericContext.Requirements = make([]swift.TargetGenericRequirementDescriptor, enum.GenericContext.Base.NumRequirements)
		for i := 0; i < int(enum.GenericContext.Base.NumRequirements); i++ {
			curr, _ = r.Seek(0, io.SeekCurrent)
			if err := enum.GenericContext.Requirements[i].Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read generic requirement: %v", err)
			}
		}
		// args := make([]swift.GenericPackShapeDescriptor, g.Base.NumKeyArguments)
		// if err := binary.Read(r, f.ByteOrder, &args); err != nil {
		// 	return fmt.Errorf("failed to read generic key arguments: %v", err)
		// }
		// _ = args // TODO: use this
	}

	if enum.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
		enum.ForeignMetadata = &swift.TargetForeignMetadataInitialization{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := enum.ForeignMetadata.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read foreign metadata initialization: %v", err)
		}
	}

	if enum.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
		enum.SingletonMetadata = &swift.TargetSingletonMetadataInitialization{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := enum.SingletonMetadata.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read singleton metadata initialization: %v", err)
		}
	}

	if enum.Flags.KindSpecific().HasCanonicalMetadataPrespecializations() {
		var lc swift.TargetCanonicalSpecializedMetadatasListCount
		if err := binary.Read(r, f.ByteOrder, &lc); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		enum.Metadatas = make([]swift.Metadata, lc.Count)
		for i := 0; i < int(lc.Count); i++ {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := enum.Metadatas[i].TargetCanonicalSpecializedMetadatasListEntry.Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read canonical metadata list entry: %v", err)
			}
		}
		enum.CachingOnceToken = &swift.TargetCanonicalSpecializedMetadatasCachingOnceToken{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := enum.CachingOnceToken.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		for idx, m := range enum.Metadatas {
			f.cr.SeekToAddr(m.Metadata.GetAddress())
			if err := binary.Read(f.cr, f.ByteOrder, &enum.Metadatas[idx].TargetMetadata); err != nil {
				return fmt.Errorf("failed to read metadata: %w", err)
			}
			enum.Metadatas[idx].TargetMetadata.TypeDescriptor = f.vma.Convert(enum.Metadatas[idx].TargetMetadata.TypeDescriptor)
			enum.Metadatas[idx].TargetMetadata.TypeMetadataAddress = f.vma.Convert(enum.Metadatas[idx].TargetMetadata.TypeMetadataAddress)
		}
	}

	if enum.NumPayloadCasesAndPayloadSizeOffset != 0 {
		// fmt.Println(enum.TargetEnumDescriptor.String())
	}

	if enum.ParentOffset.IsSet() {
		f.cr.SeekToAddr(enum.ParentOffset.GetAddress())
		ctx, err := f.getContextDesc(enum.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent = &swift.Type{
			Address: enum.ParentOffset.GetAddress(),
			Name:    ctx.Name,
			Parent: &swift.Type{
				Name: ctx.Parent,
			},
		}
	}

	typ.Name, err = f.GetCString(enum.NameOffset.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read cstring: %v", err)
	}

	if enum.FieldsOffset.IsSet() {
		if item, ok := f.swift[enum.FieldsOffset.GetAddress()]; ok { // check cache
			if fd, ok := item.(*swift.Field); ok {
				typ.Fields = fd
			}
		} else {
			f.cr.SeekToAddr(enum.FieldsOffset.GetAddress())
			fd, err := f.readField(f.cr, enum.FieldsOffset.GetAddress())
			if err != nil {
				return fmt.Errorf("failed to read swift field: %w", err)
			}
			typ.Fields = fd
		}
	}

	curr, _ := r.Seek(0, io.SeekCurrent)
	typ.Size = int64(curr - off)
	typ.Type = enum

	return nil
}

// PreCache will precache all swift fields and types (to hopefully improve performance)
func (f *File) PreCache() error {
	if _, err := f.GetSwiftFields(); err != nil {
		if !errors.Is(err, ErrSwiftSectionError) {
			return fmt.Errorf("failed to precache swift fields: %w", err)
		}
	}
	if _, err := f.GetSwiftColocateTypeDescriptors(); err != nil {
		if !errors.Is(err, ErrSwiftSectionError) {
			return fmt.Errorf("failed to precache swift types: %w", err)
		}
	}
	return nil
}

/**********
* HELPERS *
***********/

func Align(addr uint64, align uint64) uint64 {
	return (addr + align - 1) &^ (align - 1)
}

func (f *File) getAssociatedTypes(addr uint64) ([]string, error) {
	var out []string

	if err := f.cr.SeekToAddr(addr); err != nil {
		return nil, fmt.Errorf("failed to Seek to address %#x: %v", addr, err)
	}

	s, err := bufio.NewReader(f.cr).ReadString('\x00')
	if err != nil {
		return nil, fmt.Errorf("failed to read strubg at address %#x, %v", addr, err)
	}

	if len(s) > 0 {
		out = append(out, strings.Split(strings.TrimSuffix(s, "\x00"), " ")...)
	}

	return out, nil
}

func (f *File) symbolLookup(addr uint64) (string, error) {
	var err error
	var ptr uint64

	if (addr & 1) == 1 {
		addr = addr &^ 1
		ptr, err = f.GetPointerAtAddress(addr)
		if err != nil {
			return "", fmt.Errorf("failed to read protocol pointer @ %#x: %v", addr, err)
		}
		ptr = f.vma.Convert(ptr)
	} else {
		ptr = addr
	}

	if bind, err := f.GetBindName(ptr); err == nil {
		return bind, nil
	} else if syms, err := f.FindAddressSymbols(ptr); err == nil {
		if len(syms) > 0 {
			for _, s := range syms {
				if !s.Type.IsDebugSym() {
					return s.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("failed to find symbol for address %#x", addr)
}

func (f *File) getContextDesc(addr uint64) (ctx *swift.TargetModuleContext, err error) {
	var ptr uint64

	if (addr & 1) == 1 {
		addr = addr &^ 1
		ptr, err = f.GetPointerAtAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to read swift context descriptor pointer @ %#x: %v", addr, err)
		}
		ptr = f.vma.Convert(ptr)
	} else {
		ptr = addr
	}

	if err := f.cr.SeekToAddr(ptr); err != nil {
		bind, err := f.GetBindName(ptr)
		if err == nil {
			return &swift.TargetModuleContext{Name: bind}, nil
		}
		return nil, fmt.Errorf("failed to seek to swift context descriptor parent offset: %w", err)
	}

	ctx = &swift.TargetModuleContext{}
	if err := ctx.TargetModuleContextDescriptor.Read(f.cr, ptr); err != nil {
		return nil, fmt.Errorf("failed to read swift module context descriptor: %w", err)
	}

	if ctx.ParentOffset.IsSet() {
		parent, err := f.getContextDesc(ctx.ParentOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift module context name: %w", err)
		}
		ctx.Parent = parent.Name
	}

	switch ctx.Flags.Kind() {
	case swift.CDKindModule, swift.CDKindProtocol, swift.CDKindClass, swift.CDKindStruct, swift.CDKindEnum:
		if ctx.NameOffset.IsSet() {
			ctx.Name, err = f.GetCString(ctx.NameOffset.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("failed to read swift module context name: %w", err)
			}
		}
	}

	return ctx, nil
}

// ref: https://github.com/apple/swift/blob/main/lib/Demangling/Demangler.cpp (demangleSymbolicReference)
// ref: https://github.com/apple/swift/blob/main/docs/ABI/Mangling.rst#symbolic-references
func (f *File) makeSymbolicMangledNameStringRef(addr uint64) (string, error) {

	type lookup struct {
		Kind uint8
		Addr uint64
	}

	var symbolic bool
	var rawKind uint8

	parseControlData := func() ([]any, error) {
		var curr int64
		var cstring string
		var elements []any

		seqData := make([]uint8, 1)
		if err := f.cr.SeekToAddr(addr); err != nil {
			return nil, fmt.Errorf("failed to seek to swift symbolic mangled name control data addr: %w", err)
		}
		off, _ := f.cr.Seek(0, io.SeekCurrent)
		curr, _ = f.cr.Seek(0, io.SeekCurrent)
		if _, err := f.cr.Read(seqData); err != nil {
			return nil, fmt.Errorf("failed to read to swift symbolic mangled name control data: %v", err)
		}

		for {
			if seqData[0] == 0xff {
				// skip 0xff as padding
			} else if seqData[0] == 0 {
				if len(cstring) > 0 {
					elements = append(elements, cstring)
					cstring = ""
				}
				break
			} else if seqData[0] >= 0x01 && seqData[0] <= 0x17 {
				if len(cstring) > 0 {
					elements = append(elements, cstring)
					cstring = ""
				}
				symbolic = true
				rawKind = seqData[0]
				var reference int32
				if err := binary.Read(f.cr, f.ByteOrder, &reference); err != nil {
					return nil, fmt.Errorf("failed to read swift symbolic reference: %v", err)
				}
				elements = append(elements, lookup{
					Kind: seqData[0],
					Addr: addr + uint64(curr-off) + uint64(1+int64(reference)),
				})
			} else if seqData[0] >= 0x18 && seqData[0] <= 0x1f {
				if len(cstring) > 0 {
					elements = append(elements, cstring)
					cstring = ""
				}
				symbolic = true
				var reference uint64
				if err := binary.Read(f.cr, f.ByteOrder, &reference); err != nil {
					return nil, fmt.Errorf("failed to read swift symbolic reference: %v", err)
				}
				elements = append(elements, lookup{
					Kind: seqData[0],
					Addr: uint64(reference),
				})
			} else {
				cstring += string(seqData[0])
			}

			curr, _ = f.cr.Seek(0, io.SeekCurrent)
			_, err := f.cr.Read(seqData)
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, fmt.Errorf("failed to read swift symbolic reference control data: %v", err)
			}
		}
		return elements, nil
	}

	parts, err := parseControlData()
	if err != nil {
		return "", fmt.Errorf("failed to parse control data: %v", err)
	}

	var out []string

	for _, part := range parts {
		switch part := part.(type) {
		case string:
			switch part {
			case "Sg": // optional
				out = append(out, "?")
			case "SSg", "G", "x": // Swift.String?
				out = append(out, "_$sS"+part)
			default:
				if regexp.MustCompile("So[0-9]+").MatchString(part) {
					if strings.Contains(part, "OS_dispatch_queue") {
						out = append(out, "DispatchQueue")
					} else {
						out = append(out, "_$s"+part)
					}
				} else if regexp.MustCompile("^[0-9]+").MatchString(part) {
					// remove leading numbers
					for i, c := range part {
						if !unicode.IsNumber(c) {
							out = append(out, part[i:])
							break
						}
					}
				} else if strings.HasPrefix(part, "$s") {
					out = append(out, "_"+part)
				} else {
					if strings.HasPrefix(part, "S") {
						out = append(out, "_$s"+part)
					} else if strings.HasPrefix(part, "y") {
						out = append(out, "_$sSS"+part)
					} else {
						out = append(out, "_$sS"+part)
					}
				}
			}
		case lookup:
			switch part.Kind {
			case 0x01: // DIRECT symbolic reference to a context descriptor
				var name string
				if err := f.cr.SeekToAddr(part.Addr); err != nil {
					return "", fmt.Errorf("failed to seek to swift context descriptor: %v", err)
				}
				ctx, err := f.getContextDesc(part.Addr)
				if err != nil {
					return "", fmt.Errorf("failed to read indirect context descriptor: %v", err)
				}
				name = ctx.Name
				if len(ctx.Parent) > 0 {
					name = ctx.Parent + "." + name
				}
				if symbolic {
					name += "()"
				}
				out = append(out, name)
			case 0x02: // symbolic reference to a context descriptor
				var name string
				ptr, err := f.GetPointerAtAddress(part.Addr)
				if err != nil {
					return "", fmt.Errorf("failed to get pointer for indirect context descriptor: %v", err)
				}
				ptr = f.vma.Convert(ptr)
				if bind, err := f.GetBindName(ptr); err == nil {
					name = bind
				} else {
					if ptr == 0 {
						name, err = f.symbolLookup(addr)
						if err != nil {
							name = "(private)"
						}
					} else {
						if err := f.cr.SeekToAddr(f.vma.Convert(ptr)); err != nil {
							return "", fmt.Errorf("failed to seek to indirect context descriptor: %v", err)
						}
						ctx, err := f.getContextDesc(f.vma.Convert(ptr))
						if err != nil {
							return "", fmt.Errorf("failed to read indirect context descriptor: %v", err)
						}
						name = ctx.Name
						if len(ctx.Parent) > 0 {
							name = ctx.Parent + "." + name
						}
					}
				}
				if symbolic {
					name += "()"
				}
				out = append(out, name)
			case 0x09: // DIRECT symbolic reference to an accessor function, which can be executed in the process to get a pointer to the referenced entity.
				// AccessorFunctionReference
				out = append(out, fmt.Sprintf("(accessor function sub_%x)", part.Addr))
			case 0x0a: // DIRECT symbolic reference to a unique extended existential type shape.
				// UniqueExtendedExistentialTypeShape
				var name string
				if err := f.cr.SeekToAddr(part.Addr); err != nil {
					return "", fmt.Errorf("failed to seek to swift context descriptor: %v", err)
				}
				var extshape swift.TargetExtendedExistentialTypeShape
				if err := extshape.Read(f.cr, part.Addr); err != nil {
					return "", fmt.Errorf("failed to read swift context descriptor: %v", err)
				}
				name, err = f.GetCString(extshape.ExistentialType.GetAddress())
				if err != nil {
					return "", fmt.Errorf("failed to read swift context descriptor descriptor name: %v", err)
				}
				if regexp.MustCompile("^[0-9]+").MatchString(name) {
					name = "_$sl" + name
				}
				if symbolic {
					name += "()"
				}
				out = append(out, name)
			case 0x0b: // DIRECT symbolic reference to a non-unique extended existential type shape.
				// NonUniqueExtendedExistentialTypeShape
				var name string
				if err := f.cr.SeekToAddr(part.Addr); err != nil {
					return "", fmt.Errorf("failed to seek to swift context descriptor: %v", err)
				}
				var nonUnique swift.TargetNonUniqueExtendedExistentialTypeShape
				if err := nonUnique.Read(f.cr, part.Addr); err != nil {
					return "", fmt.Errorf("failed to read swift context descriptor: %v", err)
				}
				name, err = f.GetCString(nonUnique.LocalCopy.ExistentialType.GetAddress())
				if err != nil {
					return "", fmt.Errorf("failed to read swift context descriptor descriptor name: %v", err)
				}
				if regexp.MustCompile("^[0-9]+").MatchString(name) {
					name = "_$sl" + name
				}
				if symbolic {
					name += "()"
				}
				out = append(out, name)
			case 0x0c: // DIRECT symbolic reference to a objective C protocol ref.
				// ObjectiveCProtocol
				return "", fmt.Errorf("symbolic reference to a objective C protocol ref kind %x (at %#x) is not implemented (please open an issue on Github)", part.Kind, part.Addr)
			/* These are all currently reserved but unused. */
			case 0x03: // DIRECT to protocol conformance descriptor
				fallthrough
			case 0x04: // indirect to protocol conformance descriptor
				fallthrough
			case 0x05: // DIRECT to associated conformance descriptor
				fallthrough
			case 0x06: // DIRECT to associated conformance descriptor
				fallthrough
			case 0x07: // DIRECT to associated conformance access function
				fallthrough
			case 0x08: // indirect to associated conformance access function
				fallthrough
			default:
				return "", fmt.Errorf("symbolic reference control character %#x is not implemented", rawKind)
			}
		default:
			return "", fmt.Errorf("unexpected symbolic reference element type %#v", part)
		}
	}

	return strings.Join(out, " "), nil
}
