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
	"unsafe"

	"github.com/blacktop/go-macho/types/swift"
)

const sizeOfInt32 = 4
const sizeOfInt64 = 8

var ErrSwiftSectionError = fmt.Errorf("missing swift section")

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
				return nil, fmt.Errorf("failed to read swift field: %w", err)
			}

			fields = append(fields, *field)
		}

		return fields, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_fieldmd' section: %w", ErrSwiftSectionError)
}

func (f *File) readField(r io.Reader, addr uint64) (field *swift.Field, err error) {
	if typ, ok := f.swift[addr]; ok {
		if _, ok := typ.(*swift.Field); ok {
			return typ.(*swift.Field), nil
		}
	}

	field = &swift.Field{Address: addr}

	if err := field.FieldDescriptor.Read(r, addr); err != nil {
		return nil, fmt.Errorf("failed to read swift field descriptor string: %w", err)
	}

	addr += field.FieldDescriptor.Size()

	field.Records = make([]swift.FieldRecord, field.NumFields)

	for i := 0; i < int(field.NumFields); i++ {
		if err := field.Records[i].FieldRecordDescriptor.Read(r, addr); err != nil {
			return nil, fmt.Errorf("failed to read swift FieldRecordDescriptor: %v", err)
		}
		addr += field.Records[i].FieldRecordDescriptor.Size()
	}

	// parse fields
	field.Type, err = f.makeSymbolicMangledNameStringRef(field.MangledTypeNameOffset.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("failed to read swift field mangled type name: %w", err)
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

	f.swift[field.Address] = field // cache

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

		relOffsets := make([]int32, len(dat)/sizeOfInt32)
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %w", err)
		}

		for idx, relOff := range relOffsets {
			addr := uint64(int64(sec.Addr) + int64(idx*sizeOfInt32) + int64(relOff))

			f.cr.SeekToAddr(addr)

			proto, err := f.parseProtocol(f.cr, &swift.Type{Address: addr})
			if err != nil {
				return nil, fmt.Errorf("failed to read swift protocol: %w", err)
			}

			protos = append(protos, *proto)
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

		relOffsets := make([]int32, len(dat)/sizeOfInt32)
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %w", err)
		}

		for idx, relOff := range relOffsets {
			pcd, err := f.readProtocolConformance(uint64(int64(sec.Addr) + int64(idx*sizeOfInt32) + int64(relOff)))
			if err != nil {
				return nil, fmt.Errorf("failed to read swift protocol conformance: %w", err)
			}

			protoConfDescs = append(protoConfDescs, *pcd)
		}

		return protoConfDescs, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_proto' section: %w", ErrSwiftSectionError)
}

func (f *File) readProtocolConformance(addr uint64) (pcd *swift.ConformanceDescriptor, err error) {
	curr, _ := f.cr.Seek(0, io.SeekCurrent) // save offset
	defer f.cr.Seek(curr, io.SeekStart)     // reset

	f.cr.SeekToAddr(addr)

	off, _ := f.cr.Seek(0, io.SeekCurrent) // save offset

	pcd = &swift.ConformanceDescriptor{Address: addr}

	if err := pcd.TargetProtocolConformanceDescriptor.Read(f.cr, pcd.Address); err != nil {
		return nil, fmt.Errorf("failed to read swift TargetProtocolConformanceDescriptor: %v", err)
	}

	if pcd.Flags.IsRetroactive() {
		var retroactiveOffset int32
		if err := binary.Read(f.cr, f.ByteOrder, &retroactiveOffset); err != nil {
			return nil, fmt.Errorf("failed to read retroactive conformance descriptor header: %v", err)
		}
		pcd.Retroactive, err = f.getContextDesc(uint64(int64(pcd.Address) + pcd.TargetProtocolConformanceDescriptor.Size() + int64(retroactiveOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to read retroactive conformance descriptor: %v", err)
		}
	}

	if pcd.Flags.GetNumConditionalRequirements() > 0 {
		pcd.ConditionalRequirements = make([]swift.TargetGenericRequirement, pcd.Flags.GetNumConditionalRequirements())
		for i := 0; i < pcd.Flags.GetNumConditionalRequirements(); i++ {
			if err := binary.Read(f.cr, f.ByteOrder, &pcd.ConditionalRequirements[i]); err != nil {
				return nil, fmt.Errorf("failed to read conditional requirements: %v", err)
			}
		}
	}

	if pcd.Flags.NumConditionalPackShapeDescriptors() > 0 {
		var hdr swift.GenericPackShapeHeader
		if err := binary.Read(f.cr, f.ByteOrder, &hdr); err != nil {
			return nil, fmt.Errorf("failed to read conditional pack shape header: %v", err)
		}
		_ = hdr // TODO: use this
		pcd.ConditionalPackShapes = make([]swift.GenericPackShapeDescriptor, pcd.Flags.NumConditionalPackShapeDescriptors())
		if err := binary.Read(f.cr, f.ByteOrder, &pcd.ConditionalPackShapes); err != nil {
			return nil, fmt.Errorf("failed to read conditional pack shape descriptors: %v", err)
		}
	}

	if pcd.Flags.HasResilientWitnesses() {
		var rwit swift.TargetResilientWitnessesHeader
		if err := binary.Read(f.cr, f.ByteOrder, &rwit); err != nil {
			return nil, fmt.Errorf("failed to read resilient witnesses offset: %v", err)
		}
		pcd.ResilientWitnesses = make([]swift.ResilientWitnesses, rwit.NumWitnesses)
		for i := 0; i < int(rwit.NumWitnesses); i++ {
			curr, _ = f.cr.Seek(0, io.SeekCurrent) // save offset
			if err := pcd.ResilientWitnesses[i].Read(f.cr, pcd.Address+uint64(curr-off)); err != nil {
				return nil, fmt.Errorf("failed to read protocols requirements : %v", err)
			}
		}
		end, _ := f.cr.Seek(0, io.SeekCurrent)
		for idx, wit := range pcd.ResilientWitnesses {
			addr, err := wit.RequirementOff.GetAddress(f.cr, f.GetPointerAtAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to read resilient witness requirement address: %v", err)
			}
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
		f.cr.Seek(end, io.SeekStart) // reset TODO: fix this, it's dumb
	}

	if pcd.Flags.HasGenericWitnessTable() {
		if err := binary.Read(f.cr, f.ByteOrder, &pcd.GenericWitnessTable); err != nil {
			return nil, fmt.Errorf("failed to read generic witness table: %v", err)
		}
	}
	paddr, err := pcd.ProtocolOffsest.GetAddress(f.cr, f.GetPointerAtAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to read protocol offset pointer flags(%s): %v", pcd.Flags.String(), err)
	}
	pcd.Protocol, err = f.GetBindName(paddr)
	if err != nil {
		ctx, err := f.getContextDesc(paddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read protocol name: %v", err)
		}
		pcd.Protocol = ctx.Name
	}

	// parse type reference
	switch pcd.Flags.GetTypeReferenceKind() {
	case swift.DirectTypeDescriptor:
		f.cr.SeekToAddr(pcd.TypeRefOffsest.GetAddress())
		pcd.TypeRef, err = f.readType(f.cr, pcd.TypeRefOffsest.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read type: %v", err)
		}
	case swift.IndirectTypeDescriptor:
		addr := pcd.TypeRefOffsest.GetAddress()
		_ = addr
		addr = addr &^ 1
		ptr, err := f.GetPointerAtAddress(pcd.TypeRefOffsest.GetAddress() &^ 1)
		if err != nil {
			return nil, fmt.Errorf("failed to read type pointer: %v", err)
		}
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
			pcd.TypeRef, err = f.readType(f.cr, ptr)
			if err != nil {
				return nil, fmt.Errorf("failed to read type: %v", err)
			}
		}
	case swift.DirectObjCClassName:
		name, err := f.GetCString(pcd.TypeRefOffsest.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift objc class name: %v", err)
		}
		pcd.TypeRef = &swift.Type{
			Address: pcd.TypeRefOffsest.GetAddress(),
			Name:    name,
			Kind:    swift.CDKindClass,
			Parent: &swift.TargetModuleContext{
				Name: "",
			},
		}
	case swift.IndirectObjCClass:
		ptr, err := f.GetPointerAtAddress(pcd.TypeRefOffsest.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift indirect objc class name pointer: %v", err)
		}
		name, err := f.GetCString(ptr)
		if err != nil {
			return nil, fmt.Errorf("failed to read swift indirect objc class name : %v", err)
		}
		pcd.TypeRef = &swift.Type{
			Address: pcd.TypeRefOffsest.GetAddress(),
			Name:    name,
			Kind:    swift.CDKindClass,
			Parent: &swift.TargetModuleContext{
				Name: "",
			},
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

	if pcd.Flags.IsSynthesizedNonUnique() {
		pcd.TypeRef.SuperClass = "_$sSC"
	}

	return pcd, nil
}

// GetSwiftClosures parses all the closure context objects in the __TEXT.__swift5_capture section
func (f *File) GetSwiftClosures() ([]swift.Capture, error) {
	var closures []swift.Capture

	if sec := f.Section("__TEXT", "__swift5_capture"); sec != nil {
		f.cr.SeekToAddr(sec.Addr)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		for {
			currOffset, _ := r.Seek(0, io.SeekCurrent)
			currAddr := sec.Addr + uint64(currOffset)

			capture := swift.Capture{Address: currAddr}

			if err := binary.Read(r, f.ByteOrder, &capture.CaptureDescriptor); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift %T: %w", capture.CaptureDescriptor, err)
			}

			if capture.NumCaptureTypes > 0 {
				numCapsAddr := uint64(int64(currAddr) + int64(binary.Size(capture.CaptureDescriptor)))
				captureTypeRecords := make([]swift.CaptureTypeRecord, capture.NumCaptureTypes)
				if err := binary.Read(r, f.ByteOrder, &captureTypeRecords); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", captureTypeRecords, err)
				}
				for _, capRecord := range captureTypeRecords {
					name, err := f.makeSymbolicMangledNameStringRef(uint64(int64(numCapsAddr) + int64(capRecord.MangledTypeName)))
					if err != nil {
						return nil, fmt.Errorf("failed to read mangled type name @ %#x: %v", uint64(int64(numCapsAddr)+int64(capRecord.MangledTypeName)), err)
					}
					capture.CaptureTypes = append(capture.CaptureTypes, name)
					numCapsAddr += uint64(binary.Size(capRecord))
				}
			}

			if capture.NumMetadataSources > 0 {
				metadataSourceRecords := make([]swift.MetadataSourceRecord, capture.NumMetadataSources)
				if err := binary.Read(r, f.ByteOrder, &metadataSourceRecords); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", metadataSourceRecords, err)
				}
				for idx, metasource := range metadataSourceRecords {
					currAddr += uint64(idx * binary.Size(swift.MetadataSourceRecord{}))
					typeName, err := f.makeSymbolicMangledNameStringRef(uint64(int64(currAddr) + int64(metasource.MangledTypeName)))
					if err != nil {
						return nil, fmt.Errorf("failed to read mangled type name @ %#x: %v", uint64(int64(currAddr)+int64(metasource.MangledTypeName)), err)
					}
					metaSource, err := f.makeSymbolicMangledNameStringRef(uint64(int64(currAddr) + sizeOfInt32 + int64(metasource.MangledMetadataSource)))
					if err != nil {
						return nil, fmt.Errorf("failed to read mangled metadata source @ %#x: %v", uint64(int64(currAddr)+sizeOfInt32+int64(metasource.MangledMetadataSource)), err)
					}
					capture.MetadataSources = append(capture.MetadataSources, swift.MetadataSource{
						MangledType:           typeName,
						MangledMetadataSource: metaSource,
					})
				}
			}

			if capture.NumBindings > 0 {
				capture.Bindings = make([]swift.NecessaryBindings, capture.NumBindings)
				if err := binary.Read(r, f.ByteOrder, &capture.Bindings); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", capture.Bindings, err)
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
func (f *File) GetSwiftAccessibleFunctions() (*swift.AccessibleFunctionsSection, error) {
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

		var afsec swift.AccessibleFunctionsSection
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &afsec); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", afsec, err)
		}

		return &afsec, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_acfuncs' section: %w", ErrSwiftSectionError)
}

// TODO: I'm not sure we should parse this as it contains a lot of info referenced by swift runtime, but not sure I can sequentially parse it
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

// GetMultiPayloadEnums TODO: finish me
func (f *File) GetMultiPayloadEnums() (mpenums []swift.MultiPayloadEnum, err error) {
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

// GetColocateTypeDescriptors parses all the colocated type descriptors in the __TEXT.__constg_swiftt section
func (f *File) GetColocateTypeDescriptors() ([]swift.Type, error) {
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
				return nil, fmt.Errorf("failed to read swift colocate type: %w", err)
			}

			typs = append(typs, *typ)
		}

		return typs, nil
	}

	return nil, fmt.Errorf("MachO has no '__constg_swiftt' section: %w", ErrSwiftSectionError)
}

// GetColocateMetadata parses all the colocated metadata in the __TEXT.__textg_swiftm section
func (f *File) GetColocateMetadata() ([]swift.ConformanceDescriptor, error) {
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
	// if err := f.parseColocateTypeDescriptorSection(); err != nil {
	// 	return nil, fmt.Errorf("failed to parse colocated type descriptor section: %v", err)
	// }
	if sec := f.Section("__TEXT", "__swift5_types"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		relOffsets := make([]int32, len(dat)/sizeOfInt32)
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &relOffsets); err != nil {
			return nil, fmt.Errorf("failed to read relative offsets: %v", err)
		}

		for idx, relOff := range relOffsets {
			addr := uint64(int64(sec.Addr) + int64(idx*sizeOfInt32) + int64(relOff))

			f.cr.SeekToAddr(addr)

			typ, err := f.readType(f.cr, addr)
			if err != nil {
				return nil, fmt.Errorf("failed to read type: %v", err)
			}

			typs = append(typs, *typ)
		}

		return typs, nil
	}
	return nil, fmt.Errorf("MachO has no '__swift5_types' section: %w", ErrSwiftSectionError)
}

func (f *File) readType(r io.ReadSeeker, addr uint64) (typ *swift.Type, err error) {
	if typ, ok := f.swift[addr]; ok {
		if _, ok := typ.(*swift.Type); ok {
			return typ.(*swift.Type), nil
		}
	}

	var desc swift.TargetContextDescriptor
	if err := desc.Read(r, addr); err != nil {
		return nil, fmt.Errorf("failed to read swift type context descriptor: %w", err)
	}
	r.Seek(-desc.Size(), io.SeekCurrent) // rewind

	typ = &swift.Type{Address: addr, Kind: desc.Flags.Kind()}

	var metadataInitSize int

	switch desc.Flags.KindSpecific().MetadataInitialization() {
	case swift.MetadataInitNone:
		metadataInitSize = 0
	case swift.MetadataInitSingleton:
		metadataInitSize = int(swift.TargetSingletonMetadataInitialization{}.Size())
	case swift.MetadataInitForeign:
		metadataInitSize = int(swift.TargetForeignMetadataInitialization{}.Size())
	default:
		return nil, fmt.Errorf("unknown metadata initialization: %v", desc.Flags.KindSpecific().MetadataInitialization())
	}
	if metadataInitSize != 0 {
		// fmt.Println("metadataInitSize: ", metadataInitSize) // TODO: use this in size/offset calculations
	}
	switch desc.Flags.Kind() {
	case swift.CDKindModule:
		if err := f.parseModule(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case swift.CDKindExtension:
		if err := f.parseExtension(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case swift.CDKindAnonymous:
		var anon swift.TargetAnonymousContextDescriptor
		if err := binary.Read(r, f.ByteOrder, &anon); err != nil {
			return nil, fmt.Errorf("failed to read swift anonymous descriptor: %v", err)
		}
		typ.Type = &anon
	case swift.CDKindProtocol:
		if _, err := f.parseProtocol(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case swift.CDKindOpaqueType:
		var oD swift.TargetOpaqueTypeDescriptor
		if err := binary.Read(r, f.ByteOrder, &oD); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", oD, err)
		}
		typ.Type = &oD
	case swift.CDKindClass:
		if err := f.parseClassDescriptor(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case swift.CDKindStruct:
		if err := f.parseStructDescriptor(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case swift.CDKindEnum:
		if err := f.parseEnumDescriptor(r, typ); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31:
		var tdesc swift.TargetTypeContextDescriptor
		if err := tdesc.Read(r, addr); err != nil {
			return nil, fmt.Errorf("failed to read swift type context descriptor: %w", err)
		}
		typ.Type = &tdesc
		typ.Name, err = f.GetCString(tdesc.NameOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
		if tdesc.ParentOffset.IsSet() {
			typ.Parent, err = f.getContextDesc(tdesc.ParentOffset.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("failed to get parent: %v", err)
			}
		}
	default:
		return nil, fmt.Errorf("unknown swift type kind: %v", desc.Flags.Kind())
	}

	f.swift[typ.Address] = typ // cache

	return typ, nil
}

/***************
* TYPE PARSERS *
****************/

func (f *File) parseModule(r io.Reader, typ *swift.Type) (err error) {
	var desc swift.TargetModuleContextDescriptor
	if err := desc.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read swift module descriptor: %v", err)
	}
	typ.Name, err = f.GetCString(desc.NameOffset.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read type name: %v", err)
	}
	if desc.ParentOffset.IsSet() {
		typ.Parent, err = f.getContextDesc(desc.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
	}
	typ.Type = &desc
	return nil
}

func (f *File) parseExtension(r io.Reader, typ *swift.Type) (err error) {
	var desc swift.TargetExtensionContextDescriptor
	if err := desc.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read swift module descriptor: %v", err)
	}
	if desc.ParentOffset.IsSet() {
		typ.Parent, err = f.getContextDesc(desc.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
	}
	typ.Name, err = f.getCString(desc.ExtendedContext.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read extended context: %v", err)
	}
	typ.Type = &desc
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
		prot.Parent, err = f.getContextDesc(prot.ParentOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to get parent: %v", err)
		}
	}

	prot.Name, err = f.GetCString(prot.NameOffset.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	if prot.AssociatedTypeNamesOffset.IsSet() {
		prot.AssociatedTypes, err = f.getAssociatedTypes(prot.AssociatedTypeNamesOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to get associated types: %v", err)
		}
	}

	typ.Name = prot.Name
	typ.Parent = prot.Parent

	typ.Type = &prot

	return prot, nil
}

func (f *File) parseClassDescriptor(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var class swift.Class
	if err := class.TargetClassDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read %T: %v", class.TargetClassDescriptor, err)
	}

	if class.Flags.IsGeneric() {
		class.GenericContext = &swift.GenericContext{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := class.GenericContext.TargetTypeGenericContextDescriptorHeader.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		class.GenericContext.Parameters = make([]swift.GenericParamDescriptor, class.GenericContext.Base.NumParams)
		if err := binary.Read(r, f.ByteOrder, &class.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
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
		var resilient swift.TargetResilientSuperclass
		if err := resilient.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read resilient superclass: %v", err)
		}
		// class.ResilientSuperclass, err = f.makeSymbolicMangledNameStringRef(resilient.Superclass.GetAddress())
		// if err != nil {
		// 	return fmt.Errorf("failed to read swift class resilient superclass mangled name: %v", err)
		// }
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
		var v swift.VTable
		if err := binary.Read(r, f.ByteOrder, &v.TargetVTableDescriptorHeader); err != nil {
			return fmt.Errorf("failed to read vtable header: %v", err)
		}
		curr, _ := r.Seek(0, io.SeekCurrent)
		v.MethodListAddr = int64(typ.Address) + int64(curr-off)
		methods := make([]swift.TargetMethodDescriptor, v.VTableSize)
		if err := binary.Read(r, f.ByteOrder, &methods); err != nil {
			return fmt.Errorf("failed to read vtable method descriptors: %v", err)
		}
		for idx, method := range methods { // populate methods with address/sym
			if method.Flags.IsAsync() {
				trdp := swift.TargetRelativeDirectPointer{
					Address: uint64(int64(v.MethodListAddr) +
						int64(unsafe.Offsetof(method.Impl)) +
						int64(idx)*int64(binary.Size(swift.TargetMethodDescriptor{}))),
					RelOff: method.Impl,
				}
				f.cr.SeekToAddr(trdp.GetRelPtrAddress())
				maddr, err := trdp.GetAddress(f.cr)
				if err != nil {
					return fmt.Errorf("failed to read targer relative direct pointer: %v", err)
				}
				v.Methods = append(v.Methods, swift.Method{
					TargetMethodDescriptor: method,
					Address:                maddr,
				})
			} else {
				m := swift.Method{
					TargetMethodDescriptor: method,
					Address: uint64(int64(v.MethodListAddr) +
						int64(method.Impl) +
						int64(idx)*int64(binary.Size(swift.TargetMethodDescriptor{})) +
						int64(unsafe.Offsetof(method.Impl))),
				}
				if syms, err := f.FindAddressSymbols(m.Address); err == nil {
					if len(syms) > 0 {
						for _, s := range syms {
							if !s.Type.IsDebugSym() {
								m.Symbol = s.Name
								break
							}
						}
					}
				}
				v.Methods = append(v.Methods, m)
			}
		}
		class.VTable = &v
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

	if class.Flags.KindSpecific().HasResilientSuperclass() {
		extra := swift.ExtraClassDescriptorFlags(class.MetadataPositiveSizeInWordsORExtraClassFlags)
		if extra == swift.HasObjCResilientClassStub {
			curr, _ := r.Seek(0, io.SeekCurrent)
			if err := class.ObjCResilientClassStubInfo.Read(r, typ.Address+uint64(curr-off)); err != nil {
				return fmt.Errorf("failed to read objc resilient class stub: %v", err)
			}
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
		// typ.FieldOffsets = make([]int32, desc.NumFields)
		// if err := binary.Read(r, f.ByteOrder, &typ.FieldOffsets); err != nil {
		// 	return fmt.Errorf("failed to read field offset vector: %v", err)
		// }
		// FIXME: what the hell are field offset vectors?
	}

	if class.SuperclassType.IsSet() {
		typ.SuperClass, err = f.makeSymbolicMangledNameStringRef(class.SuperclassType.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to read swift class superclass mangled name: %v", err)
		}
	}

	typ.Name, err = f.GetCString(class.NameOffset.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read cstring: %v", err)
	}

	if class.ParentOffset.IsSet() {
		typ.Parent, err = f.getContextDesc(class.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
	}

	if class.FieldsOffset.IsSet() {
		fd, err := f.readField(f.cr, class.FieldsOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to read swift field: %w", err)
		}
		typ.Fields = append(typ.Fields, *fd)
	}

	typ.Type = &class

	return nil
}

func (f *File) parseStructDescriptor(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var st swift.Struct
	if err := st.TargetStructDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read %T: %v", st.TargetStructDescriptor, err)
	}

	if st.Flags.IsGeneric() {
		st.GenericContext = &swift.GenericContext{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := st.GenericContext.TargetTypeGenericContextDescriptorHeader.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		st.GenericContext.Parameters = make([]swift.GenericParamDescriptor, st.GenericContext.Base.NumParams)
		if err := binary.Read(r, f.ByteOrder, &st.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
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
		typ.Parent, err = f.getContextDesc(st.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
	}

	if st.FieldsOffset.IsSet() {
		f.cr.SeekToAddr(st.FieldsOffset.GetAddress())
		fd, err := f.readField(f.cr, st.FieldsOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to read swift field: %w", err)
		}
		typ.Fields = append(typ.Fields, *fd)
	}

	typ.Type = &st

	return nil
}

func (f *File) parseEnumDescriptor(r io.ReadSeeker, typ *swift.Type) (err error) {
	off, _ := r.Seek(0, io.SeekCurrent) // save offset

	var enum swift.Enum
	if err := enum.TargetEnumDescriptor.Read(r, typ.Address); err != nil {
		return fmt.Errorf("failed to read %T: %v", enum.TargetEnumDescriptor, err)
	}

	if enum.Flags.IsGeneric() {
		enum.GenericContext = &swift.GenericContext{}
		curr, _ := r.Seek(0, io.SeekCurrent)
		if err := enum.GenericContext.TargetTypeGenericContextDescriptorHeader.Read(r, typ.Address+uint64(curr-off)); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		enum.GenericContext.Parameters = make([]swift.GenericParamDescriptor, enum.GenericContext.Base.NumParams)
		if err := binary.Read(r, f.ByteOrder, &enum.GenericContext.Parameters); err != nil {
			return fmt.Errorf("failed to read generic params: %v", err)
		}
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

	// if desc.NumPayloadCasesAndPayloadSizeOffset != 0 {
	// 	fmt.Println("NumPayloadCasesAndPayloadSizeOffset: ", desc.NumPayloadCasesAndPayloadSizeOffset)
	// }

	if enum.ParentOffset.IsSet() {
		typ.Parent, err = f.getContextDesc(enum.ParentOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to get parent: %v", err)
		}
	}

	typ.Name, err = f.getCString(enum.NameOffset.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to read cstring: %v", err)
	}

	if enum.FieldsOffset.IsSet() {
		f.cr.SeekToAddr(enum.FieldsOffset.GetAddress())
		fd, err := f.readField(f.cr, enum.FieldsOffset.GetAddress())
		if err != nil {
			return fmt.Errorf("failed to read swift field: %w", err)
		}
		typ.Fields = append(typ.Fields, *fd)
	}

	typ.Type = &enum

	return nil
}

/**********
* HELPERS *
***********/

func (f *File) getCString(addr uint64) (string, error) {
	name, err := f.GetCString(addr)
	if err != nil {
		return "", fmt.Errorf("failed to read cstring: %v", err)
	}
	if strings.HasPrefix(name, "So8") {
		name = "_$s" + name
	}
	return name, nil
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

func (f *File) getNameStringRef(addr uint64) (string, error) {
	var err error
	var ptr uint64

	if (addr & 1) == 1 {
		addr = addr &^ 1
		ptr, err = f.GetPointerAtAddress(addr)
		if err != nil {
			return "", fmt.Errorf("failed to read protocol pointer @ %#x: %v", addr, err)
		}
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
	return f.getCString(f.vma.Convert(ptr))
}

func (f *File) getContextDesc(addr uint64) (*swift.TargetModuleContext, error) {
	var err error

	curr, _ := f.cr.Seek(0, io.SeekCurrent)
	defer f.cr.Seek(curr, io.SeekStart)

	var ptr uint64

	if (addr & 1) == 1 {
		addr = addr &^ 1
		ptr, err = f.GetPointerAtAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to read swift context descriptor pointer @ %#x: %v", addr, err)
		}
	} else {
		ptr = addr
	}

	if err := f.cr.SeekToAddr(ptr); err != nil {
		return nil, fmt.Errorf("failed to seek to swift context descriptor parent offset: %w", err)
	}

	var tmc swift.TargetModuleContext
	if err := tmc.TargetModuleContextDescriptor.Read(f.cr, ptr); err != nil {
		return nil, fmt.Errorf("failed to read swift module context descriptor: %w", err)
	}

	if tmc.Flags.Kind() != swift.CDKindAnonymous {
		tmc.Name, err = f.getCString(tmc.NameOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift module context name: %w", err)
		}
	} else {
		parent, err := f.getContextDesc(tmc.ParentOffset.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read swift module context name: %w", err)
		}
		tmc.Name = parent.Name
	}

	return &tmc, nil
}

// ref: https://github.com/apple/swift/blob/main/lib/Demangling/Demangler.cpp (demangleSymbolicReference)
// ref: https://github.com/apple/swift/blob/main/docs/ABI/Mangling.rst#symbolic-references
func (f *File) makeSymbolicMangledNameStringRef(addr uint64) (string, error) {

	var symbolic bool
	var rawKind uint8
	type lookup struct {
		Kind uint8
		Addr uint64
	}

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
			if seqData[0] == 0x00 {
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
				var desc swift.TargetModuleContextDescriptor
				if err := desc.Read(f.cr, part.Addr); err != nil {
					return "", fmt.Errorf("failed to read swift context descriptor: %v", err)
				}
				name, err = f.GetCString(desc.NameOffset.GetAddress())
				if err != nil {
					return "", fmt.Errorf("failed to read swift context descriptor descriptor name: %v", err)
				}
				if desc.ParentOffset.IsSet() {
					parent, err := f.getContextDesc(desc.ParentOffset.GetAddress())
					if err != nil {
						return "", fmt.Errorf("failed to read swift context descriptor parent: %v", err)
					}
					if len(parent.Name) > 0 {
						name = parent.Name + "." + name
					}
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
				if f.HasFixups() {
					if dcf, err := f.DyldChainedFixups(); err == nil {
						if _, _, ok := dcf.IsBind(ptr); ok {
							name, err = f.GetBindName(ptr)
							if err != nil {
								return "", fmt.Errorf("failed to read protocol name: %v", err)
							}
						}
					}
				}
				if len(name) == 0 {
					if err := f.cr.SeekToAddr(f.vma.Convert(ptr)); err != nil {
						return "", fmt.Errorf("failed to seek to indirect context descriptor: %v", err)
					}
					var desc swift.TargetModuleContextDescriptor
					if err := desc.Read(f.cr, f.vma.Convert(ptr)); err != nil {
						return "", fmt.Errorf("failed to read swift context descriptor: %v", err)
					}
					name, err = f.GetCString(desc.NameOffset.GetAddress())
					if err != nil {
						return "", fmt.Errorf("failed to read swift context descriptor descriptor name: %v", err)
					}
					if desc.ParentOffset.IsSet() {
						parent, err := f.getContextDesc(desc.ParentOffset.GetAddress())
						if err != nil {
							return "", fmt.Errorf("failed to read swift context descriptor parent: %v", err)
						}
						if len(parent.Name) > 0 {
							name = parent.Name + "." + name
						}
					}
				}
				if symbolic {
					name += "()"
				}
				out = append(out, name)
			case 0x09: // DIRECT symbolic reference to an accessor function, which can be executed in the process to get a pointer to the referenced entity.
				// AccessorFunctionReference
				panic("not implemented")
			case 0x0a: // DIRECT symbolic reference to a unique extended existential type shape.
				// UniqueExtendedExistentialTypeShape
				panic("not implemented")
			case 0x0b: // DIRECT symbolic reference to a non-unique extended existential type shape.
				// NonUniqueExtendedExistentialTypeShape
				panic("not implemented")
			case 0x0c: // DIRECT symbolic reference to a objective C protocol ref.
				// ObjectiveCProtocol
				panic("not implemented")
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
