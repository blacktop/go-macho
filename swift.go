package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
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

			field := swift.Field{
				Address: sec.Addr + uint64(curr),
			}

			field.FieldDescriptor, err = swift.ReadFieldDescriptor(r, sec.Addr+uint64(curr))
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift field descriptor string: %w", err)
			}

			for i := 0; i < int(field.NumFields); i++ {
				curr, _ = r.Seek(0, io.SeekCurrent)
				fdr, err := swift.ReadFieldRecordDescriptor(r, sec.Addr+uint64(curr))
				if err != nil {
					return nil, fmt.Errorf("failed to read swift FieldRecordDescriptor: %v", err)
				}
				field.Records = append(field.Records, swift.FieldRecord{
					FieldRecordDescriptor: fdr,
				})
			}

			fields = append(fields, field)
		}

		// parse fields
		for idx, fd := range fields {
			fields[idx].Type, err = f.makeSymbolicMangledNameStringRef(fd.MangledTypeNameOffset.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("failed to read swift field mangled type name: %w", err)
			}

			if fd.SuperclassOffset.RelOff != 0 {
				fields[idx].SuperClass, err = f.makeSymbolicMangledNameStringRef(fd.SuperclassOffset.GetAddress())
				if err != nil {
					return nil, fmt.Errorf("failed to read swift field super class mangled name: %w", err)
				}
			}

			for ridx, rec := range fd.Records {
				if rec.MangledTypeNameOffset.RelOff != 0 {
					fields[idx].Records[ridx].MangledType, err = f.makeSymbolicMangledNameStringRef(rec.MangledTypeNameOffset.GetAddress())
					if err != nil {
						return nil, fmt.Errorf("failed to read swift field record mangled type name; %w", err)
					}
				}

				fields[idx].Records[ridx].Name, err = f.GetCString(rec.FieldNameOffset.GetAddress())
				if err != nil {
					return nil, fmt.Errorf("failed to read swift field record name cstring: %w", err)
				}
			}
		}

		return fields, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_fieldmd' section: %w", ErrSwiftSectionError)
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

			atyp.AssociatedTypeDescriptor, err = swift.ReadAssociatedTypeDescriptor(r, sec.Addr+uint64(curr))
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift AssociatedTypeDescriptor: %w", err)
			}

			atyp.TypeRecords = make([]swift.ATRecordType, atyp.NumAssociatedTypes)
			for i := uint32(0); i < atyp.NumAssociatedTypes; i++ {
				curr, _ = r.Seek(0, io.SeekCurrent)
				atyp.TypeRecords[i].AssociatedTypeRecord, err = swift.ReadAssociatedTypeRecord(r, sec.Addr+uint64(curr))
				if err != nil {
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
			proto, err := f.readProtocol(uint64(int64(sec.Addr) + int64(idx*sizeOfInt32) + int64(relOff)))
			if err != nil {
				return nil, fmt.Errorf("failed to read swift protocol: %w", err)
			}

			protos = append(protos, *proto)
		}

		return protos, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_protos' section: %w", ErrSwiftSectionError)
}

func (f *File) readProtocol(addr uint64) (proto *swift.Protocol, err error) {
	curr, _ := f.cr.Seek(0, io.SeekCurrent) // save offset
	defer f.cr.Seek(curr, io.SeekStart)     // reset

	f.cr.SeekToAddr(addr)

	proto = &swift.Protocol{
		Address: addr,
	}

	if err := binary.Read(f.cr, f.ByteOrder, &proto.TargetProtocolDescriptor); err != nil {
		return nil, fmt.Errorf("failed to read swift protocol descriptor: %v", err)
	}

	if proto.NumRequirementsInSignature > 0 {
		proto.SignatureRequirements = make([]swift.TargetGenericRequirement, proto.NumRequirementsInSignature)
		for i := 0; i < int(proto.NumRequirementsInSignature); i++ {
			if err := binary.Read(f.cr, f.ByteOrder, &proto.SignatureRequirements[i].TargetGenericRequirementDescriptor); err != nil {
				return nil, fmt.Errorf("failed to read protocols requirements in signature : %v", err)
			}
		}

		// currentAddr := addr + uint64(binary.Size(proto.Header))

		// for idx, req := range proto.SignatureRequirements {
		// 	currentAddr += uint64(idx * binary.Size(swift.TargetGenericRequirementDescriptor{}))
		// 	proto.SignatureRequirements[idx].Name, err = f.makeSymbolicMangledNameStringRef(uint64(int64(currentAddr) + sizeOfInt32 + int64(req.Param)))
		// 	if err != nil {
		// 		return nil, fmt.Errorf("failed to read protocols requirements in signature : %v", err)
		// 	}
		// 	switch req.Flags.Kind() {
		// 	case swift.GRKindProtocol:
		// 		address := uint64(int64(currentAddr) + int64(sizeOfInt32*2) + int64(req.TypeOrProtocolOrConformanceOrLayout))
		// 		var ptr uint64
		// 		if (req.TypeOrProtocolOrConformanceOrLayout & 1) == 1 {
		// 			address = address &^ 1
		// 			ptr, _ = f.GetPointerAtAddress(address)
		// 		} else {
		// 			ptr = uint64(int64(currentAddr) + int64(sizeOfInt32*2) + int64(req.TypeOrProtocolOrConformanceOrLayout))
		// 		}
		// 		if f.HasFixups() {
		// 			dcf, err := f.DyldChainedFixups()
		// 			if err != nil {
		// 				return nil, fmt.Errorf("failed to get dyld chained fixups: %v", err)
		// 			}
		// 			if _, _, ok := dcf.IsBind(ptr); ok {
		// 				proto.SignatureRequirements[idx].Kind, err = f.GetBindName(ptr)
		// 				if err != nil {
		// 					return nil, fmt.Errorf("failed to read protocol name: %v", err)
		// 				}
		// 			} else {
		// 				proto.SignatureRequirements[idx].Kind, err = f.GetCString(f.vma.Convert(ptr))
		// 				if err != nil {
		// 					return nil, fmt.Errorf("failed to read protocol name: %v", err)
		// 				}
		// 			}
		// 		} else { // TODO: fix this (redundant???)
		// 			proto.SignatureRequirements[idx].Kind, err = f.GetCString(f.vma.Convert(ptr))
		// 			if err != nil {
		// 				return nil, fmt.Errorf("failed to read protocol name: %v", err)
		// 			}
		// 		}
		// 	case swift.GRKindSameType:
		// 		fmt.Println("same type")
		// 	case swift.GRKindSameConformance:
		// 		fmt.Println("same conformance")
		// 	case swift.GRKindLayout:
		// 		fmt.Println("layout")
		// 	}
		// 	fmt.Printf("%s (%s): %s\n", proto.SignatureRequirements[idx].Name, proto.SignatureRequirements[idx].Kind, req.Flags)
		// }
	}

	if proto.NumRequirements > 0 {
		curr, _ := f.cr.Seek(0, io.SeekCurrent) // save offset
		proto.Requirements = make([]swift.TargetProtocolRequirement, proto.NumRequirements)
		if err := binary.Read(f.cr, f.ByteOrder, &proto.Requirements); err != nil {
			return nil, fmt.Errorf("failed to read protocols requirements: %v", err)
		}
		for idx, req := range proto.Requirements {
			if req.DefaultImplementation != 0 {
				raddr := uint64(int64(addr) + curr + int64(idx*binary.Size(req)) + int64(req.DefaultImplementation))
				fmt.Printf("%#x: flags: %s\n", raddr, req.Flags)
			}
		}
	}

	if proto.ParentOffset != 0 {
		parentAddr := uint64(int64(addr) + int64(unsafe.Offsetof(proto.ParentOffset)) + int64(proto.ParentOffset))
		parent, err := f.getContextDesc(parentAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read swift protocol descriptor parent: %v", err)
		}
		proto.Parent = parent.Name
	}

	proto.Name, err = f.GetCString(uint64(int64(addr) + int64(unsafe.Offsetof(swift.TargetProtocolDescriptor{}.NameOffset)) + int64(proto.NameOffset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read swift protocol name: %v", err)
	}

	if proto.AssociatedTypeNamesOffset != 0 {
		proto.AssociatedType, err = f.GetCString(uint64(int64(addr) + int64(unsafe.Offsetof(swift.TargetProtocolDescriptor{}.AssociatedTypeNamesOffset)) + int64(proto.AssociatedTypeNamesOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to read protocols assocated type names: %v", err)
		}
	}

	return proto, nil
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

	if err := pcd.ReadDescriptor(f.cr); err != nil {
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
		curr, _ := f.cr.Seek(0, io.SeekCurrent)
		wits := make([]swift.TargetResilientWitness, rwit.NumWitnesses)
		if err := binary.Read(f.cr, f.ByteOrder, &wits); err != nil {
			return nil, fmt.Errorf("failed to read resilient witnesses offset: %v", err)
		}
		end, _ := f.cr.Seek(0, io.SeekCurrent)
		for idx, wit := range wits {
			addr := uint64(int64(pcd.Address) + (curr - off) + int64(idx*binary.Size(swift.TargetResilientWitness{})) + int64(wit.Requirement))
			req, err := f.getNameStringRef(addr)
			if err != nil {
				return nil, fmt.Errorf("failed to read resilient witness requirement: %v", err)
			}
			impl := uint64(int64(pcd.Address) + (curr - off) + int64(idx*binary.Size(swift.TargetResilientWitness{})) + int64(unsafe.Offsetof(wit.Impl)) + int64(wit.Impl))
			pcd.ResilientWitnesses = append(pcd.ResilientWitnesses, swift.ResilientWitnesses{
				Implementation:      impl,
				ProtocolRequirement: req,
			})
		}
		f.cr.Seek(end, io.SeekStart) // reset TODO: fix this, it's dumb
	}

	if pcd.Flags.HasGenericWitnessTable() {
		if err := binary.Read(f.cr, f.ByteOrder, &pcd.GenericWitnessTable); err != nil {
			return nil, fmt.Errorf("failed to read generic witness table: %v", err)
		}
	}

	pcd.Protocol, err = f.getNameStringRef(pcd.ProtocolOffsest.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("failed to read protocol name: %v", err)
	}
	fmt.Println(pcd.Flags.String())
	// if pcd.Flags.IsSynthesizedNonUnique() {

	// }

	if pcd.WitnessTablePatternOffsest.RelOff > 0 {
		ptr, err := f.GetPointerAtAddress(pcd.WitnessTablePatternOffsest.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to read witness table pattern pointer: %v", err)
		}
		// ptr += f.preferredLoadAddress()
		// _ = ptr // TODO: use this
		// f.cr.SeekToAddr(wtpAddr)
		// var wt swift.TargetWitnessTable
		// if err := binary.Read(f.cr, f.ByteOrder, &wt); err != nil {
		// 	return nil, fmt.Errorf("failed to read witness table pattern: %v", err)
		// }
		if ptr != pcd.Address && ptr+f.preferredLoadAddress() != pcd.Address {
			wtp, err := f.readProtocolConformance(ptr)
			if err != nil {
				return nil, fmt.Errorf("failed to read conformance descriptor witness table pattern: %v", err)
			}
			pcd.WitnessTablePattern = wtp.Protocol
		}
	}

	// FIXME: uncomment this when we can parse type references again

	// parse type reference
	// switch pcd.Flags.GetTypeReferenceKind() {
	// case swift.DirectTypeDescriptor:
	// 	pcd.TypeRef, err = f.readTypeAtAddress(pcd.TypeRefOffsest.GetAddress())
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read type: %v", err)
	// 	}
	// case swift.IndirectTypeDescriptor:
	// 	ptr, err := f.GetPointerAtAddress(pcd.TypeRefOffsest.GetAddress())
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read type pointer: %v", err)
	// 	}
	// 	if ptr == 0 {
	// 		bind, err := f.GetBindName(pcd.TypeRefOffsest.GetAddress())
	// 		if err == nil {
	// 			pcd.TypeRef = &swift.Type{
	// 				Address: ptr,
	// 				Name:    bind,
	// 			}
	// 		}
	// 	} else {
	// 		pcd.TypeRef, err = f.readTypeAtAddress(f.vma.Convert(ptr))
	// 		if err != nil {
	// 			return nil, fmt.Errorf("failed to read type: %v", err)
	// 		}
	// 	}
	// case swift.DirectObjCClassName:
	// 	name, err := f.GetCString(pcd.TypeRefOffsest.GetAddress())
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read swift objc class name: %v", err)
	// 	}
	// 	pcd.TypeRef = &swift.Type{
	// 		Address: pcd.TypeRefOffsest.GetAddress(),
	// 		Name:    name,
	// 	}
	// case swift.IndirectObjCClass:
	// 	ptr, err := f.GetPointerAtAddress(pcd.TypeRefOffsest.GetAddress())
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read swift indirect objc class name pointer: %v", err)
	// 	}
	// 	name, err := f.GetCString(ptr)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read swift indirect objc class name : %v", err)
	// 	}
	// 	pcd.TypeRef = &swift.Type{
	// 		Address: pcd.TypeRefOffsest.GetAddress(),
	// 		Name:    name,
	// 	}
	// }

	// if pcd.Flags.IsSynthesizedNonUnique() {
	// 	pcd.TypeRef.SuperClass = "_$sSC"
	// }

	return
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
			typ, err := f.readTypeAtAddress(uint64(int64(sec.Addr) + int64(idx*sizeOfInt32) + int64(relOff)))
			if err != nil {
				return nil, fmt.Errorf("failed to read type: %v", err)
			}

			typs = append(typs, *typ)
		}

		return typs, nil
	}
	return nil, fmt.Errorf("MachO has no '__swift5_types' section: %w", ErrSwiftSectionError)
}

func (f *File) readTypeAtAddress(addr uint64) (*swift.Type, error) {
	var err error
	var typ swift.Type

	f.cr.SeekToAddr(addr)

	var tDesc swift.TargetTypeContextDescriptor
	if err := binary.Read(f.cr, f.ByteOrder, &tDesc); err != nil {
		return nil, fmt.Errorf("failed to read swift type context descriptor: %v", err)
	}

	off, _ := f.cr.Seek(-int64(binary.Size(tDesc)), io.SeekCurrent) // rewind

	typ.Address = addr
	typ.Kind = tDesc.Flags.Kind()

	var metadataInitSize int

	switch tDesc.Flags.KindSpecific().MetadataInitialization() {
	case swift.MetadataInitNone:
		metadataInitSize = 0
	case swift.MetadataInitSingleton:
		metadataInitSize = binary.Size(swift.TargetSingletonMetadataInitialization{})
	case swift.MetadataInitForeign:
		metadataInitSize = binary.Size(swift.TargetForeignMetadataInitialization{})
	default:
		return nil, fmt.Errorf("unknown metadata initialization: %v", tDesc.Flags.KindSpecific().MetadataInitialization())
	}
	if metadataInitSize != 0 {
		// fmt.Println("metadataInitSize: ", metadataInitSize) // TODO: use this in size/offset calculations
	}

	switch typ.Kind {
	case swift.CDKindModule:
		var mod swift.TargetModuleContextDescriptor
		if err := binary.Read(f.cr, f.ByteOrder, &mod); err != nil {
			return nil, fmt.Errorf("failed to read swift module descriptor: %v", err)
		}
		typ.Type = &mod
	case swift.CDKindExtension:
		var ext swift.TargetExtensionContextDescriptor
		if err := binary.Read(f.cr, f.ByteOrder, &ext); err != nil {
			return nil, fmt.Errorf("failed to read swift extension descriptor: %v", err)
		}
		typ.Type = &ext
	case swift.CDKindAnonymous:
		var anon swift.TargetAnonymousContextDescriptor
		if err := binary.Read(f.cr, f.ByteOrder, &anon); err != nil {
			return nil, fmt.Errorf("failed to read swift anonymous descriptor: %v", err)
		}
		typ.Type = &anon
	case swift.CDKindProtocol:
		var pD swift.TargetProtocolDescriptor
		if err := binary.Read(f.cr, f.ByteOrder, &pD); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", pD, err)
		}
		typ.Type = &pD
	case swift.CDKindOpaqueType:
		var oD swift.TargetOpaqueTypeDescriptor
		if err := binary.Read(f.cr, f.ByteOrder, &oD); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", oD, err)
		}
		typ.Type = &oD
	case swift.CDKindClass:
		if err := f.parseClassDescriptor(&typ, int64(addr), off); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case swift.CDKindStruct:
		if err := f.parseStructDescriptor(&typ, addr); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case swift.CDKindEnum:
		if err := f.parseEnumDescriptor(&typ, addr); err != nil {
			return nil, fmt.Errorf("failed to read type kind %s: %w", typ.Kind, err)
		}
	case 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31:
		typ.Type = &tDesc
	default:
		return nil, fmt.Errorf("unknown swift type kind: %v", typ.Kind)
	}

	typ.Name, err = f.GetCString(uint64(int64(typ.Address) + int64(sizeOfInt32*2) + int64(tDesc.NameOffset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	if tDesc.ParentOffset != 0 {
		typ.Parent.Address = uint64(int64(typ.Address) + sizeOfInt32 + int64(tDesc.ParentOffset))
		parent, err := f.getContextDesc(typ.Parent.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to get parent: %v", err)
		}
		typ.Parent.Name = parent.Name
	}

	typ.AccessFunction = uint64(int64(typ.Address) + int64(sizeOfInt32*3) + int64(tDesc.AccessFunctionPtr))

	if tDesc.FieldsOffset != 0 {
		// fd, err := f.parseField(uint64(int64(addr)+int64(sizeOfInt32*4)+int64(tDesc.FieldsOffset)), typ.FieldOffsets...)
		// if err != nil {
		// 	return nil, fmt.Errorf("failed to read swift field: %v", err)
		// }
		// typ.Fields = append(typ.Fields, fd)
	}

	return &typ, nil
}

func (f *File) readType(r *bytes.Reader, addr uint64) (typ *swift.Type, err error) {

	var tcDesc swift.TargetContextDescriptor
	if err := binary.Read(r, f.ByteOrder, &tcDesc); err != nil {
		return nil, fmt.Errorf("failed to read swift type context descriptor: %w", err)
	}

	off, _ := r.Seek(-int64(binary.Size(tcDesc)), io.SeekCurrent) // rewind

	typ = &swift.Type{
		Address: addr,
		Kind:    tcDesc.Flags.Kind(),
	}

	if tcDesc.ParentOffset < 0 {
		typ.Parent.Address = uint64(int64(typ.Address) + sizeOfInt32 + int64(tcDesc.ParentOffset))
		parent, err := f.getContextDesc(typ.Parent.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to get parent: %w", err)
		}
		typ.Parent.Name = parent.Name
	}

	var metadataInitSize int

	switch tcDesc.Flags.KindSpecific().MetadataInitialization() {
	case swift.MetadataInitNone:
		metadataInitSize = 0
	case swift.MetadataInitSingleton:
		metadataInitSize = binary.Size(swift.TargetSingletonMetadataInitialization{})
	case swift.MetadataInitForeign:
		metadataInitSize = binary.Size(swift.TargetForeignMetadataInitialization{})
	}
	if metadataInitSize != 0 {
		// fmt.Println("metadataInitSize: ", metadataInitSize) // TODO: use this in size/offset calculations
	}

	switch typ.Kind {
	case swift.CDKindModule:
		var mod swift.TargetModuleContextDescriptor
		if err := binary.Read(r, f.ByteOrder, &mod); err != nil {
			return nil, fmt.Errorf("failed to read swift module descriptor: %v", err)
		}
		typ.Type = &mod
		typ.Name, err = f.GetCString(uint64(int64(typ.Address) + int64(unsafe.Offsetof(mod.NameOffset)) + int64(mod.NameOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	case swift.CDKindExtension:
		var ext swift.TargetExtensionContextDescriptor
		if err := binary.Read(r, f.ByteOrder, &ext); err != nil {
			return nil, fmt.Errorf("failed to read swift extension descriptor: %v", err)
		}
		typ.Type = &ext
	case swift.CDKindAnonymous:
		var anon swift.TargetAnonymousContextDescriptor
		if err := binary.Read(r, f.ByteOrder, &anon); err != nil {
			return nil, fmt.Errorf("failed to read swift anonymous descriptor: %v", err)
		}
		typ.Type = &anon
	case swift.CDKindProtocol:
		var pD swift.TargetProtocolDescriptor
		if err := binary.Read(r, f.ByteOrder, &pD); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", pD, err)
		}
		typ.Type = &pD
	case swift.CDKindOpaqueType:
		var oD swift.TargetOpaqueTypeDescriptor
		if err := binary.Read(r, f.ByteOrder, &oD); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", oD, err)
		}
		typ.Type = &oD
	case swift.CDKindClass:
		var cD swift.TargetClassDescriptor
		if err := binary.Read(r, f.ByteOrder, &cD); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", cD, err)
		}
		if cD.Flags.IsGeneric() {
			var g swift.TargetTypeGenericContextDescriptorHeader
			if err := binary.Read(r, f.ByteOrder, &g); err != nil {
				return nil, fmt.Errorf("failed to read generic header: %v", err)
			}
			typ.Generic = &g
		}
		if cD.Flags.KindSpecific().HasResilientSuperclass() {
			extra := swift.ExtraClassDescriptorFlags(cD.MetadataPositiveSizeInWordsORExtraClassFlags)
			_ = extra // TODO: use this
			var resilient swift.TargetResilientSuperclass
			if err := binary.Read(r, f.ByteOrder, &resilient); err != nil {
				return nil, fmt.Errorf("failed to read resilient superclass: %v", err)
			}
			_ = resilient // TODO: use this
		}
		if cD.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
			var md swift.TargetForeignMetadataInitialization
			if err := binary.Read(r, f.ByteOrder, &md); err != nil {
				return nil, fmt.Errorf("failed to read foreign metadata initialization: %v", err)
			}
			_ = md // TODO: use this
		}
		if cD.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
			var smi swift.TargetSingletonMetadataInitialization
			if err := binary.Read(r, f.ByteOrder, &smi); err != nil {
				return nil, fmt.Errorf("failed to read singleton metadata initialization: %v", err)
			}
			_ = smi // TODO: use this
		}
		if cD.Flags.KindSpecific().HasVTable() {
			var v swift.VTable
			if err := binary.Read(r, f.ByteOrder, &v.TargetVTableDescriptorHeader); err != nil {
				return nil, fmt.Errorf("failed to read vtable header: %v", err)
			}
			curr, _ := r.Seek(0, io.SeekCurrent)
			v.MethodListOffset = int64(addr) + int64(curr-off)
			methods := make([]swift.TargetMethodDescriptor, v.VTableSize)
			if err := binary.Read(r, f.ByteOrder, &methods); err != nil {
				return nil, fmt.Errorf("failed to read vtable method descriptors: %v", err)
			}
			for idx, method := range methods { // populate methods with address/sym
				if method.Flags.IsAsync() {
					v.Methods = append(v.Methods, swift.Method{
						TargetMethodDescriptor: method,
					})
				} else {
					m := swift.Method{
						TargetMethodDescriptor: method,
						Address: uint64(int64(v.MethodListOffset) +
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
			typ.VTable = &v
		}
		if cD.Flags.KindSpecific().HasOverrideTable() {
			var o swift.TargetOverrideTableHeader
			if err := binary.Read(r, f.ByteOrder, &o); err != nil {
				return nil, fmt.Errorf("failed to read override table header: %v", err)
			}
			entries := make([]swift.TargetMethodOverrideDescriptor, o.NumEntries)
			if err := binary.Read(r, f.ByteOrder, &entries); err != nil {
				return nil, fmt.Errorf("failed to read override table entries: %v", err)
			}
		}
		if cD.Flags.KindSpecific().HasResilientSuperclass() {
			extra := swift.ExtraClassDescriptorFlags(cD.MetadataPositiveSizeInWordsORExtraClassFlags)
			if extra == swift.HasObjCResilientClassStub {
				var stub swift.TargetObjCResilientClassStubInfo
				if err := binary.Read(r, f.ByteOrder, &stub); err != nil {
					return nil, fmt.Errorf("failed to read objc resilient class stub: %v", err)
				}
				_ = stub // TODO: use this
			}
		}
		if cD.Flags.KindSpecific().HasCanonicalMetadataPrespecializations() {
			var md swift.TargetCanonicalSpecializedMetadatasListCount
			if err := binary.Read(r, f.ByteOrder, &md); err != nil {
				return nil, fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
			}
			for i := 0; i < int(md.Count); i++ {
				var le swift.TargetCanonicalSpecializedMetadatasListEntry
				if err := binary.Read(r, f.ByteOrder, &le); err != nil {
					return nil, fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
				}
				_ = le // TODO: use this
			}
			var cache swift.TargetCanonicalSpecializedMetadatasCachingOnceToken
			if err := binary.Read(r, f.ByteOrder, &cache); err != nil {
				return nil, fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
			}
			_ = cache // TODO: use this
		}
		// if cD.FieldOffsetVectorOffset != 0 {
		// 	if cD.Flags.KindSpecific().HasResilientSuperclass() {
		// 		cD.FieldOffsetVectorOffset += cD.MetadataNegativeSizeInWordsORResilientMetadataBounds
		// 	}
		// 	typ.FieldOffsets = make([]int32, cD.NumFields)
		// 	if err := binary.Read(r, f.ByteOrder, &typ.FieldOffsets); err != nil {
		// 		return nil, fmt.Errorf("failed to read field offset vector: %v", err)
		// 	}
		// }
		typ.Type = &cD
		typ.Name, err = f.GetCString(uint64(int64(typ.Address) + int64(unsafe.Offsetof(cD.NameOffset)) + int64(cD.NameOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
		typ.AccessFunction = uint64(int64(typ.Address) + int64(sizeOfInt32*3) + int64(cD.AccessFunctionPtr))
	case swift.CDKindStruct:
		var sD swift.TargetStructDescriptor
		if err := binary.Read(r, f.ByteOrder, &sD); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", sD, err)
		}
		if sD.Flags.IsGeneric() {
			var g swift.TargetTypeGenericContextDescriptorHeader
			if err := binary.Read(f.cr, f.ByteOrder, &g); err != nil {
				return nil, fmt.Errorf("failed to read generic header: %v", err)
			}
			typ.Generic = &g
		}
		if sD.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
			var md swift.TargetForeignMetadataInitialization
			if err := binary.Read(r, f.ByteOrder, &md); err != nil {
				return nil, fmt.Errorf("failed to read foreign metadata initialization: %v", err)
			}
			_ = md // TODO: use this
		}
		if sD.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
			var smi swift.TargetSingletonMetadataInitialization
			if err := binary.Read(r, f.ByteOrder, &smi); err != nil {
				return nil, fmt.Errorf("failed to read singleton metadata initialization: %v", err)
			}
			_ = smi // TODO: use this
		}
		if sD.Flags.KindSpecific().HasCanonicalMetadataPrespecializations() {
			var md swift.TargetCanonicalSpecializedMetadatasListCount
			if err := binary.Read(r, f.ByteOrder, &md); err != nil {
				return nil, fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
			}
			for i := 0; i < int(md.Count); i++ {
				var le swift.TargetCanonicalSpecializedMetadatasListEntry
				if err := binary.Read(r, f.ByteOrder, &le); err != nil {
					return nil, fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
				}
				_ = le // TODO: use this
			}
			var cache swift.TargetCanonicalSpecializedMetadatasCachingOnceToken
			if err := binary.Read(r, f.ByteOrder, &cache); err != nil {
				return nil, fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
			}
			_ = cache // TODO: use this
		}
		// if sD.FieldOffsetVectorOffset != 0 {
		// 	typ.FieldOffsets = make([]int32, sD.NumFields)
		// 	if err := binary.Read(r, f.ByteOrder, &typ.FieldOffsets); err != nil {
		// 		return nil, fmt.Errorf("failed to read field offset vector: %v", err)
		// 	}
		// }
		typ.Type = &sD
		typ.Name, err = f.GetCString(uint64(int64(typ.Address) + int64(unsafe.Offsetof(sD.NameOffset)) + int64(sD.NameOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	case swift.CDKindEnum:
		var eD swift.TargetEnumDescriptor
		if err := binary.Read(r, f.ByteOrder, &eD); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", eD, err)
		}
		if eD.Flags.IsGeneric() {
			var g swift.TargetTypeGenericContextDescriptorHeader
			if err := binary.Read(r, f.ByteOrder, &g); err != nil {
				return nil, fmt.Errorf("failed to read generic header: %v", err)
			}
			typ.Generic = &g
		}
		if eD.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
			var md swift.TargetForeignMetadataInitialization
			if err := binary.Read(r, f.ByteOrder, &md); err != nil {
				return nil, fmt.Errorf("failed to read foreign metadata initialization: %v", err)
			}
			_ = md // TODO: use this
		}
		if eD.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
			var smi swift.TargetSingletonMetadataInitialization
			if err := binary.Read(r, f.ByteOrder, &smi); err != nil {
				return nil, fmt.Errorf("failed to read singleton metadata initialization: %v", err)
			}
			_ = smi // TODO: use this
		}
		typ.Type = &eD
		typ.Name, err = f.GetCString(uint64(int64(typ.Address) + int64(unsafe.Offsetof(eD.NameOffset)) + int64(eD.NameOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	case 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31:
		typ.Type = tcDesc
	default:
		return nil, fmt.Errorf("unknown swift type kind: %v", typ.Kind)
	}

	// typ.Name, err = f.GetCString(uint64(int64(typ.Address) + int64(sizeOfInt32*2) + int64(tcDesc.NameOffset)))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read cstring: %v", err)
	// }

	// typ.AccessFunction = uint64(int64(typ.Address) + int64(sizeOfInt32*3) + int64(tcDesc.AccessFunctionPtr))

	// if typ.VTable != nil {
	// 	fmt.Println("METHODS")
	// 	for idx, m := range typ.VTable.GetMethods() {
	// 		fmt.Printf("%2d)  flags: %s", idx, m.Flags)
	// 		if m.Flags.IsAsync() {
	// 			fmt.Println("ASYNC")
	// 		}
	// 		var sym string
	// 		syms, _ := f.FindAddressSymbols(m.Address)
	// 		if len(syms) > 0 {
	// 			for _, s := range syms {
	// 				if !s.Type.IsDebugSym() {
	// 					sym = s.Name
	// 					break
	// 				}
	// 			}
	// 		}
	// 		// fmt.Printf("      impl:    %d\n", m.Impl)
	// 		fmt.Printf(" address: %#x\tsym: %s\n", m.Address, sym)
	// 	}
	// }

	// if lentyp.FieldOffsets != 0 {
	// 	fd, err := f.readField(uint64(int64(addr)+int64(sizeOfInt32*4)+int64(tcDesc.FieldsOffset)), typ.FieldOffsets...)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read swift field: %v", err)
	// 	}

	// 	typ.Fields = append(typ.Fields, fd)
	// }

	return
}

func (f *File) parseClassDescriptor(typ *swift.Type, addr, off int64) (err error) {
	var desc swift.TargetClassDescriptor
	if err := binary.Read(f.cr, f.ByteOrder, &desc); err != nil {
		return fmt.Errorf("failed to read %T: %v", desc, err)
	}

	if desc.Flags.IsGeneric() {
		var g swift.TargetTypeGenericContextDescriptorHeader
		if err := binary.Read(f.cr, f.ByteOrder, &g); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		typ.Generic = &g
	}

	if desc.Flags.KindSpecific().HasResilientSuperclass() {
		extra := swift.ExtraClassDescriptorFlags(desc.MetadataPositiveSizeInWordsORExtraClassFlags)
		_ = extra // TODO: use this
		var resilient swift.TargetResilientSuperclass
		if err := binary.Read(f.cr, f.ByteOrder, &resilient); err != nil {
			return fmt.Errorf("failed to read resilient superclass: %v", err)
		}
		_ = resilient // TODO: use this
	}

	if desc.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
		var fmd swift.TargetForeignMetadataInitialization
		if err := binary.Read(f.cr, f.ByteOrder, &fmd); err != nil {
			return fmt.Errorf("failed to read foreign metadata initialization: %v", err)
		}
		_ = fmd // TODO: use this (pattern is always null)
	}

	if desc.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
		var smi swift.TargetSingletonMetadataInitialization
		if err := binary.Read(f.cr, f.ByteOrder, &smi); err != nil {
			return fmt.Errorf("failed to read singleton metadata initialization: %v", err)
		}
		_ = smi // TODO: use this
	}

	if desc.Flags.KindSpecific().HasVTable() {
		var v swift.VTable
		if err := binary.Read(f.cr, f.ByteOrder, &v.TargetVTableDescriptorHeader); err != nil {
			return fmt.Errorf("failed to read vtable header: %v", err)
		}
		curr, _ := f.cr.Seek(0, io.SeekCurrent)
		v.MethodListOffset = int64(addr) + int64(curr-off)
		methods := make([]swift.TargetMethodDescriptor, v.VTableSize)
		if err := binary.Read(f.cr, f.ByteOrder, &methods); err != nil {
			return fmt.Errorf("failed to read vtable method descriptors: %v", err)
		}
		for idx, method := range methods { // populate methods with address/sym
			if method.Flags.IsAsync() {
				v.Methods = append(v.Methods, swift.Method{
					TargetMethodDescriptor: method,
				})
			} else {
				m := swift.Method{
					TargetMethodDescriptor: method,
					Address: uint64(int64(v.MethodListOffset) +
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
		typ.VTable = &v
	}

	if desc.Flags.KindSpecific().HasOverrideTable() {
		var o swift.TargetOverrideTableHeader
		if err := binary.Read(f.cr, f.ByteOrder, &o); err != nil {
			return fmt.Errorf("failed to read override table header: %v", err)
		}
		entries := make([]swift.TargetMethodOverrideDescriptor, o.NumEntries)
		if err := binary.Read(f.cr, f.ByteOrder, &entries); err != nil {
			return fmt.Errorf("failed to read override table entries: %v", err)
		}
	}

	if desc.Flags.KindSpecific().HasResilientSuperclass() {
		extra := swift.ExtraClassDescriptorFlags(desc.MetadataPositiveSizeInWordsORExtraClassFlags)
		if extra == swift.HasObjCResilientClassStub {
			var stub swift.TargetObjCResilientClassStubInfo
			if err := binary.Read(f.cr, f.ByteOrder, &stub); err != nil {
				return fmt.Errorf("failed to read objc resilient class stub: %v", err)
			}
			_ = stub // TODO: use this
		}
	}

	if desc.Flags.KindSpecific().HasCanonicalMetadataPrespecializations() {
		var md swift.TargetCanonicalSpecializedMetadatasListCount
		if err := binary.Read(f.cr, f.ByteOrder, &md); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		for i := 0; i < int(md.Count); i++ {
			var le swift.TargetCanonicalSpecializedMetadatasListEntry
			if err := binary.Read(f.cr, f.ByteOrder, &le); err != nil {
				return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
			}
			_ = le // TODO: use this
		}
		var cache swift.TargetCanonicalSpecializedMetadatasCachingOnceToken
		if err := binary.Read(f.cr, f.ByteOrder, &cache); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		_ = cache // TODO: use this
	}

	if desc.FieldOffsetVectorOffset != 0 {
		if desc.Flags.KindSpecific().HasResilientSuperclass() {
			desc.FieldOffsetVectorOffset += desc.MetadataNegativeSizeInWordsORResilientMetadataBounds
		}
		typ.FieldOffsets = make([]int32, desc.NumFields)
		if err := binary.Read(f.cr, f.ByteOrder, &typ.FieldOffsets); err != nil {
			return fmt.Errorf("failed to read field offset vector: %v", err)
		}
	}

	if desc.SuperclassType != 0 {
		typ.SuperClass, err = f.makeSymbolicMangledNameStringRef(uint64(int64(addr) + int64(unsafe.Offsetof(desc.SuperclassType)) + int64(desc.SuperclassType)))
		if err != nil {
			return fmt.Errorf("failed to read swift class superclass mangled name: %v", err)
		}
	}

	typ.Type = &desc

	return nil
}

func (f *File) parseStructDescriptor(typ *swift.Type, addr uint64) (err error) {
	var desc swift.TargetStructDescriptor
	if err := binary.Read(f.cr, f.ByteOrder, &desc); err != nil {
		return fmt.Errorf("failed to read %T: %v", desc, err)
	}

	if desc.Flags.IsGeneric() {
		var g swift.TargetTypeGenericContextDescriptorHeader
		if err := binary.Read(f.cr, f.ByteOrder, &g); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		typ.Generic = &g
	}

	if desc.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
		var fmd swift.TargetForeignMetadataInitialization
		if err := binary.Read(f.cr, f.ByteOrder, &fmd); err != nil {
			return fmt.Errorf("failed to read foreign metadata initialization: %v", err)
		}
		_ = fmd // TODO: use this (pattern is always null)
	}

	if desc.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
		var sing swift.TargetSingletonMetadataInitialization
		if err := binary.Read(f.cr, f.ByteOrder, &sing); err != nil {
			return fmt.Errorf("failed to read singleton metadata initialization: %v", err)
		}
		_ = sing // TODO: use this
	}

	if desc.Flags.KindSpecific().HasCanonicalMetadataPrespecializations() {
		var lc swift.TargetCanonicalSpecializedMetadatasListCount
		if err := binary.Read(f.cr, f.ByteOrder, &lc); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		for i := 0; i < int(lc.Count); i++ {
			var le swift.TargetCanonicalSpecializedMetadatasListEntry
			if err := binary.Read(f.cr, f.ByteOrder, &le); err != nil {
				return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
			}
			_ = le // TODO: use this
		}
	}

	typ.Type = &desc

	return nil
}

func (f *File) parseEnumDescriptor(typ *swift.Type, addr uint64) (err error) {
	var desc swift.TargetEnumDescriptor
	if err := binary.Read(f.cr, f.ByteOrder, &desc); err != nil {
		return fmt.Errorf("failed to read %T: %v", desc, err)
	}

	if desc.Flags.IsGeneric() {
		var g swift.TargetTypeGenericContextDescriptorHeader
		if err := binary.Read(f.cr, f.ByteOrder, &g); err != nil {
			return fmt.Errorf("failed to read generic header: %v", err)
		}
		typ.Generic = &g
	}

	if desc.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitForeign {
		var fmd swift.TargetForeignMetadataInitialization
		if err := binary.Read(f.cr, f.ByteOrder, &fmd); err != nil {
			return fmt.Errorf("failed to read foreign metadata initialization: %v", err)
		}
		_ = fmd // TODO: use this (pattern is always null)
	}

	if desc.Flags.KindSpecific().MetadataInitialization() == swift.MetadataInitSingleton {
		var sing swift.TargetSingletonMetadataInitialization
		if err := binary.Read(f.cr, f.ByteOrder, &sing); err != nil {
			return fmt.Errorf("failed to read singleton metadata initialization: %v", err)
		}
		_ = sing // TODO: use this
	}

	if desc.Flags.KindSpecific().HasCanonicalMetadataPrespecializations() {
		var lc swift.TargetCanonicalSpecializedMetadatasListCount
		if err := binary.Read(f.cr, f.ByteOrder, &lc); err != nil {
			return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
		}
		for i := 0; i < int(lc.Count); i++ {
			var le swift.TargetCanonicalSpecializedMetadatasListEntry
			if err := binary.Read(f.cr, f.ByteOrder, &le); err != nil {
				return fmt.Errorf("failed to read canonical metadata prespecialization: %v", err)
			}
			_ = le // TODO: use this
		}
	}

	// if desc.NumPayloadCasesAndPayloadSizeOffset != 0 {
	// 	fmt.Println("NumPayloadCasesAndPayloadSizeOffset: ", desc.NumPayloadCasesAndPayloadSizeOffset)
	// }

	typ.Type = &desc

	return nil
}

// GetSwiftClosures parses all the closure context objects in the __TEXT.__swift5_capture section
func (f *File) GetSwiftClosures() ([]swift.CaptureDescriptor, error) {
	var closures []swift.CaptureDescriptor

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

			capture := swift.CaptureDescriptor{Address: currAddr}

			if err := binary.Read(r, f.ByteOrder, &capture.CaptureDescriptorHeader); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to read swift %T: %w", capture.CaptureDescriptorHeader, err)
			}

			if capture.NumCaptureTypes > 0 {
				numCapsAddr := uint64(int64(currAddr) + int64(binary.Size(capture.CaptureDescriptorHeader)))
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

// GetSwiftTypeRefs parses all the type references in the __TEXT.__swift5_typeref section
func (f *File) GetSwiftTypeRefs() ([]string, error) {
	var typeRefs []string
	if sec := f.Section("__TEXT", "__swift5_typeref"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

		dat := make([]byte, sec.Size)
		if err := binary.Read(f.cr, f.ByteOrder, dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewBuffer(dat)

		for {
			s, err := r.ReadString('\x00')
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read from type ref string pool: %v", err)
			}

			s = strings.TrimSpace(strings.Trim(s, "\x00"))

			if len(s) > 0 {
				typeRefs = append(typeRefs, s)
			}
		}

		return typeRefs, nil
	}

	return nil, fmt.Errorf("MachO has no '__swift5_typeref' section: %w", ErrSwiftSectionError)
}

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

			fmt.Println(sizeFlags.String())

			if sizeFlags.UsesPayloadSpareBits() {
				var psbmask swift.MultiPayloadEnumPayloadSpareBitMaskByteCount
				if err := binary.Read(r, f.ByteOrder, &psbmask); err != nil {
					return nil, fmt.Errorf("failed to read %T: %w", psbmask, err)
				}
				fmt.Println(psbmask.String())
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

			f.swift[typ.Address] = typ
			typs = append(typs, *typ)
		}

		return typs, nil
	}

	return nil, fmt.Errorf("MachO has no '__constg_swiftt' section: %w", ErrSwiftSectionError)
}

// TODO: finish me
func (f *File) GetColocateMetadata() ([]swift.ConformanceDescriptor, error) {

	if sec := f.Section("__TEXT", "__textg_swiftm"); sec != nil {
		off, err := f.vma.GetOffset(f.vma.Convert(sec.Addr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
		}
		f.cr.Seek(int64(off), io.SeekStart)

	}
	return nil, fmt.Errorf("MachO has no '__textg_swiftm' section: %w", ErrSwiftSectionError)
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
	} else {
		return f.GetCString(f.vma.Convert(ptr))
	}
}

func (f *File) getContextDesc(addr uint64) (*swift.TargetModuleContext, error) {
	var err error

	curr, _ := f.cr.Seek(0, io.SeekCurrent)
	defer f.cr.Seek(curr, io.SeekStart)

	if err := f.cr.SeekToAddr(addr); err != nil {
		return nil, fmt.Errorf("failed to seek to swift context descriptor parent offset: %w", err)
	}

	var tmc swift.TargetModuleContext
	if err := binary.Read(f.cr, f.ByteOrder, &tmc.TargetModuleContextDescriptor); err != nil {
		return nil, fmt.Errorf("failed to read type swift context descriptor parent type context descriptor: %w", err)
	}

	if tmc.Flags.Kind() != swift.CDKindAnonymous {
		tmc.Name, err = f.GetCString(uint64(int64(addr) + int64(unsafe.Offsetof(tmc.NameOffset)) + int64(tmc.NameOffset)))
		if err != nil {
			return nil, fmt.Errorf("failed to read swift module context name: %w", err)
		}
	}

	return &tmc, nil
}

// ref: https://github.com/apple/swift/blob/1a7146fb04665e2434d02bada06e6296f966770b/lib/Demangling/Demangler.cpp#L155
// ref: https://github.com/apple/swift/blob/main/docs/ABI/Mangling.rst#symbolic-references
func (f *File) makeSymbolicMangledNameStringRef(addr uint64) (string, error) {

	var name string
	var symbolic bool

	f.cr.SeekToAddr(addr)

	controlData := make([]byte, 9)
	f.cr.Read(controlData)

	if controlData[0] >= 0x01 && controlData[0] <= 0x17 {
		var reference int32
		if err := binary.Read(bytes.NewReader(controlData[1:]), f.ByteOrder, &reference); err != nil {
			return "", fmt.Errorf("failed to read swift symbolic reference: %v", err)
		}
		symbolic = true
		addr += uint64(1 + int64(reference))
	} else if controlData[0] >= 0x18 && controlData[0] <= 0x1f {
		var reference uint64
		if err := binary.Read(bytes.NewReader(controlData[1:]), f.ByteOrder, &reference); err != nil {
			return "", fmt.Errorf("failed to read swift symbolic reference: %v", err)
		}
		symbolic = true
		addr = uint64(reference)
	} else {
		name, err := f.GetCString(addr)
		if err != nil {
			return "", fmt.Errorf("failed to read swift symbolic reference @ %#x: %v", addr, err)
		}
		if strings.HasPrefix(name, "S") || strings.HasPrefix(name, "y") {
			return "_$s" + name, nil
		} else if strings.HasPrefix(name, "$s") {
			return "_" + name, nil
		}
		return name, nil
	}

	f.cr.SeekToAddr(addr)

	switch uint8(controlData[0]) {
	case 1: // Reference points directly to context descriptor
		var err error
		var tDesc swift.TargetModuleContextDescriptor
		if err := binary.Read(f.cr, f.ByteOrder, &tDesc); err != nil {
			return "", fmt.Errorf("failed to read swift context descriptor: %v", err)
		}
		name, err = f.GetCString(uint64(int64(addr) + int64(unsafe.Offsetof(tDesc.NameOffset)) + int64(tDesc.NameOffset)))
		if err != nil {
			return "", fmt.Errorf("failed to read swift context descriptor descriptor name: %v", err)
		}
		if tDesc.ParentOffset != 0 {
			parent, err := f.getContextDesc(uint64(int64(addr) + int64(unsafe.Offsetof(tDesc.ParentOffset)) + int64(tDesc.ParentOffset)))
			if err != nil {
				return "", fmt.Errorf("failed to read swift context descriptor parent: %v", err)
			}
			if len(parent.Name) > 0 {
				name = parent.Name + "." + name
			}
		}
	case 2: // Reference points indirectly to context descriptor
		ptr, err := f.GetPointerAtAddress(addr)
		if err != nil {
			return "", fmt.Errorf("failed to get pointer for indirect context descriptor: %v", err)
		}
		if f.HasFixups() {
			dcf, err := f.DyldChainedFixups()
			if err != nil {
				return "", fmt.Errorf("failed to get dyld chained fixups: %v", err)
			}
			if _, _, ok := dcf.IsBind(ptr); ok {
				name, err = f.GetBindName(ptr)
				if err != nil {
					return "", fmt.Errorf("failed to read protocol name: %v", err)
				}
			} else {
				if err := f.cr.SeekToAddr(f.vma.Convert(ptr)); err != nil {
					return "", fmt.Errorf("failed to seek to indirect context descriptor: %v", err)
				}
				var tDesc swift.TargetModuleContextDescriptor
				if err := binary.Read(f.cr, f.ByteOrder, &tDesc); err != nil {
					return "", fmt.Errorf("failed to read indirect context descriptor: %v", err)
				}
				name, err = f.GetCString(ptr + uint64(sizeOfInt32*2) + uint64(tDesc.NameOffset))
				if err != nil {
					return "", fmt.Errorf("failed to read indirect context descriptor name: %v", err)
				}
				if tDesc.ParentOffset != 0 {
					parentAddr := f.vma.Convert(ptr) + sizeOfInt32 + uint64(tDesc.ParentOffset)
					if err := f.cr.SeekToAddr(parentAddr); err != nil {
						return "", fmt.Errorf("failed to seek to indirect context descriptor parent: %v", err)
					}
					var parentDesc swift.TargetModuleContextDescriptor
					if err := binary.Read(f.cr, f.ByteOrder, &parentDesc); err != nil {
						return "", fmt.Errorf("failed to read type swift indirect context descriptor parent type context descriptor: %v", err)
					}
					parent, err := f.GetCString(parentAddr + uint64(sizeOfInt32*2) + uint64(parentDesc.NameOffset))
					if err != nil {
						return "", fmt.Errorf("failed to read indirect context descriptor name: %v", err)
					}
					if len(parent) > 0 {
						name = parent + "." + name
					}
				}
			}
		} else { // TODO: fix this (redundant???)
			name, err = f.GetCString(f.vma.Convert(ptr))
			if err != nil {
				return "", fmt.Errorf("failed to read protocol name: %v", err)
			}
		}
	case 3: // Reference points directly to protocol conformance descriptor (NOT IMPLEMENTED)
		return "", fmt.Errorf("symbolic reference control character %#x is not implemented", controlData[0])
	case 4: // Reference points indirectly to protocol conformance descriptor (NOT IMPLEMENTED)
		fallthrough
	case 5: // Reference points directly to associated conformance descriptor (NOT IMPLEMENTED)
		fallthrough
	case 6: // Reference points indirectly to associated conformance descriptor (NOT IMPLEMENTED)
		fallthrough
	case 7: // Reference points directly to associated conformance access function relative to the protocol
		fallthrough
	case 8: // Reference points indirectly to associated conformance access function relative to the protocol
		fallthrough
	case 9: // Reference points directly to metadata access function that can be invoked to produce referenced object
		// kind = SymbolicReferenceKind::AccessorFunctionReference; TODO: implement
		// direct = Directness::Direct;
		fallthrough
	case 10: // Reference points directly to an ExtendedExistentialTypeShape
		// kind = SymbolicReferenceKind::UniqueExtendedExistentialTypeShape;  TODO: implement
		// direct = Directness::Direct;
		fallthrough
	case 11: // Reference points directly to a NonUniqueExtendedExistentialTypeShape
		// kind = SymbolicReferenceKind::NonUniqueExtendedExistentialTypeShape;
		// direct = Directness::Direct;
		fallthrough
	default:
		// return "", fmt.Errorf("symbolic reference control character %#x is not implemented", controlData[0])
		return "(error)", nil
	}

	if symbolic {
		return "symbolic " + name, nil
	} else {
		return name, nil
	}
}
