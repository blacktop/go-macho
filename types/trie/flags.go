package trie

import "strings"

type CacheExportFlag int

const (
	exportSymbolFlagsKindMask        CacheExportFlag = 0x03
	exportSymbolFlagsKindRegular     CacheExportFlag = 0x00
	exportSymbolFlagsKindThreadLocal CacheExportFlag = 0x01
	exportSymbolFlagsKindAbsolute    CacheExportFlag = 0x02
	exportSymbolFlagsWeakDefinition  CacheExportFlag = 0x04
	exportSymbolFlagsReexport        CacheExportFlag = 0x08
	exportSymbolFlagsStubAndResolver CacheExportFlag = 0x10
)

func (f CacheExportFlag) Regular() bool {
	return (f & exportSymbolFlagsKindMask) == exportSymbolFlagsKindRegular
}
func (f CacheExportFlag) ThreadLocal() bool {
	return (f & exportSymbolFlagsKindMask) == exportSymbolFlagsKindThreadLocal
}
func (f CacheExportFlag) Absolute() bool {
	return (f & exportSymbolFlagsKindMask) == exportSymbolFlagsKindAbsolute
}
func (f CacheExportFlag) WeakDefinition() bool {
	return f == exportSymbolFlagsWeakDefinition
}
func (f CacheExportFlag) ReExport() bool {
	return f == exportSymbolFlagsReexport
}
func (f CacheExportFlag) StubAndResolver() bool {
	return f == exportSymbolFlagsStubAndResolver
}
func (f CacheExportFlag) String() string {
	var fStr string
	if f.Regular() {
		fStr += "Regular "
		if f.StubAndResolver() {
			fStr += "(Has Resolver Function)"
		} else if f.WeakDefinition() {
			fStr += "(Weak Definition)"
		}
	} else if f.ThreadLocal() {
		fStr += "Thread Local"
	} else if f.Absolute() {
		fStr += "Absolute"
	}
	return strings.TrimSpace(fStr)
}
