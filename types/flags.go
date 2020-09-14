package types

import "strings"

const (
	/* The following are used to encode rebasing information */
	REBASE_TYPE_POINTER                              = 1
	REBASE_TYPE_TEXT_ABSOLUTE32                      = 2
	REBASE_TYPE_TEXT_PCREL32                         = 3
	REBASE_OPCODE_MASK                               = 0xF0
	REBASE_IMMEDIATE_MASK                            = 0x0F
	REBASE_OPCODE_DONE                               = 0x00
	REBASE_OPCODE_SET_TYPE_IMM                       = 0x10
	REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        = 0x20
	REBASE_OPCODE_ADD_ADDR_ULEB                      = 0x30
	REBASE_OPCODE_ADD_ADDR_IMM_SCALED                = 0x40
	REBASE_OPCODE_DO_REBASE_IMM_TIMES                = 0x50
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES               = 0x60
	REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB            = 0x70
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80
)
const (
	/* The following are used to encode binding information */
	BIND_TYPE_POINTER                                        = 1
	BIND_TYPE_TEXT_ABSOLUTE32                                = 2
	BIND_TYPE_TEXT_PCREL32                                   = 3
	BIND_SPECIAL_DYLIB_SELF                                  = 0
	BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE                       = -1
	BIND_SPECIAL_DYLIB_FLAT_LOOKUP                           = -2
	BIND_SPECIAL_DYLIB_WEAK_LOOKUP                           = -3
	BIND_SYMBOL_FLAGS_WEAK_IMPORT                            = 0x1
	BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION                    = 0x8
	BIND_OPCODE_MASK                                         = 0xF0
	BIND_IMMEDIATE_MASK                                      = 0x0F
	BIND_OPCODE_DONE                                         = 0x00
	BIND_OPCODE_SET_DYLIB_ORDINAL_IMM                        = 0x10
	BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB                       = 0x20
	BIND_OPCODE_SET_DYLIB_SPECIAL_IMM                        = 0x30
	BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM                = 0x40
	BIND_OPCODE_SET_TYPE_IMM                                 = 0x50
	BIND_OPCODE_SET_ADDEND_SLEB                              = 0x60
	BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB                  = 0x70
	BIND_OPCODE_ADD_ADDR_ULEB                                = 0x80
	BIND_OPCODE_DO_BIND                                      = 0x90
	BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB                        = 0xA0
	BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED                  = 0xB0
	BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB             = 0xC0
	BIND_OPCODE_THREADED                                     = 0xD0
	BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0x00
	BIND_SUBOPCODE_THREADED_APPLY                            = 0x01
)

type ExportFlag int

const (
	/*
	 * The following are used on the flags byte of a terminal node
	 * in the export information.
	 */
	EXPORT_SYMBOL_FLAGS_KIND_MASK         ExportFlag = 0x03
	EXPORT_SYMBOL_FLAGS_KIND_REGULAR      ExportFlag = 0x00
	EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL ExportFlag = 0x01
	EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE     ExportFlag = 0x02
	EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION   ExportFlag = 0x04
	EXPORT_SYMBOL_FLAGS_REEXPORT          ExportFlag = 0x08
	EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER ExportFlag = 0x10
)

func (f ExportFlag) Regular() bool {
	return (f & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_REGULAR
}
func (f ExportFlag) ThreadLocal() bool {
	return (f & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL
}
func (f ExportFlag) Absolute() bool {
	return (f & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
}
func (f ExportFlag) WeakDefinition() bool {
	return f == EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION
}
func (f ExportFlag) ReExport() bool {
	return f == EXPORT_SYMBOL_FLAGS_REEXPORT
}
func (f ExportFlag) StubAndResolver() bool {
	return f == EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER
}
func (f ExportFlag) String() string {
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
