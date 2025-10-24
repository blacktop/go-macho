package macho

import (
	"strings"

	"github.com/blacktop/go-macho/types/objc"
)

// ObjCResolver exposes Objective-C metadata lookups for bridging with Swift.
type ObjCResolver interface {
	ResolveObjCProtocolName(addr uint64) (string, bool)
	ResolveObjCClassName(addr uint64) (string, bool)
}

// ResolveObjCProtocolName attempts to resolve the Objective-C protocol referenced at addr.
func (f *File) ResolveObjCProtocolName(addr uint64) (string, bool) {
	return f.resolveObjCProtocolName(addr, make(map[uint64]struct{}))
}

func (f *File) resolveObjCProtocolName(addr uint64, visited map[uint64]struct{}) (string, bool) {
	if addr == 0 {
		return "", false
	}
	if _, seen := visited[addr]; seen {
		return "", false
	}
	visited[addr] = struct{}{}

	if name, ok := f.lookupCachedObjCProtocol(addr); ok {
		return name, true
	}
	if clean := addr &^ 1; clean != addr {
		if name, ok := f.resolveObjCProtocolName(clean, visited); ok {
			return name, true
		}
	}
	if proto, err := f.getObjcProtocol(addr); err == nil && proto != nil {
		return proto.Name, true
	}
	if bind, err := f.GetBindName(addr); err == nil {
		return trimObjCProtocolSymbol(bind), true
	}
	if sym, err := f.symbolLookup(addr); err == nil && sym != "" {
		return trimObjCProtocolSymbol(sym), true
	}
	if ptr, err := f.GetPointerAtAddress(addr); err == nil && ptr != 0 && ptr != addr {
		return f.resolveObjCProtocolName(ptr, visited)
	}
	return "", false
}

// ResolveObjCClassName attempts to resolve an Objective-C class name at addr.
func (f *File) ResolveObjCClassName(addr uint64) (string, bool) {
	return f.resolveObjCClassName(addr, make(map[uint64]struct{}))
}

func (f *File) resolveObjCClassName(addr uint64, visited map[uint64]struct{}) (string, bool) {
	if addr == 0 {
		return "", false
	}
	if _, seen := visited[addr]; seen {
		return "", false
	}
	visited[addr] = struct{}{}

	if name, ok := f.lookupCachedObjCClass(addr); ok {
		return name, true
	}
	if clean := addr &^ 1; clean != addr {
		if name, ok := f.resolveObjCClassName(clean, visited); ok {
			return name, true
		}
	}
	if cls, err := f.GetObjCClass(addr); err == nil && cls != nil {
		return cls.Name, true
	}
	if bind, err := f.GetBindName(addr); err == nil {
		return trimObjCClassSymbol(bind), true
	}
	if sym, err := f.symbolLookup(addr); err == nil && sym != "" {
		return trimObjCClassSymbol(sym), true
	}
	if ptr, err := f.GetPointerAtAddress(addr); err == nil && ptr != 0 && ptr != addr {
		return f.resolveObjCClassName(ptr, visited)
	}
	return "", false
}

func trimObjCProtocolSymbol(name string) string {
	name = strings.TrimPrefix(name, "OBJC_PROTOCOL_$_")
	name = strings.TrimPrefix(name, "_OBJC_PROTOCOL_$_")
	return name
}

func trimObjCClassSymbol(name string) string {
	name = strings.TrimPrefix(name, "_OBJC_CLASS_$_")
	name = strings.TrimPrefix(name, "OBJC_CLASS_$_")
	return name
}

func (f *File) lookupCachedObjCProtocol(addr uint64) (string, bool) {
	if obj, ok := f.GetObjC(addr); ok {
		if proto, ok := obj.(*objc.Protocol); ok && proto != nil {
			return proto.Name, true
		}
	}
	if rebased := f.rebasePtr(addr); rebased != addr {
		if obj, ok := f.GetObjC(rebased); ok {
			if proto, ok := obj.(*objc.Protocol); ok && proto != nil {
				return proto.Name, true
			}
		}
	}
	return "", false
}

func (f *File) lookupCachedObjCClass(addr uint64) (string, bool) {
	if obj, ok := f.GetObjC(addr); ok {
		if cls, ok := obj.(*objc.Class); ok && cls != nil {
			return cls.Name, true
		}
	}
	if rebased := f.rebasePtr(addr); rebased != addr {
		if obj, ok := f.GetObjC(rebased); ok {
			if cls, ok := obj.(*objc.Class); ok && cls != nil {
				return cls.Name, true
			}
		}
	}
	return "", false
}
