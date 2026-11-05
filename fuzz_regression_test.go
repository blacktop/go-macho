// Regression tests for malformed Mach-O inputs found by fuzzing
// (FuzzNewFile / FuzzNewFatFile). Each test drives one crash class that used
// to panic or allocate out of range and now must be rejected with an error.

package macho

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
)

// thinImage64 wraps pre-encoded load commands (each already carrying its
// cmd/cmdsize prefix) in a minimal arm64 Mach-O header.
func thinImage64(loads ...[]byte) []byte {
	le := binary.LittleEndian
	var l bytes.Buffer
	for _, ld := range loads {
		l.Write(ld)
	}
	out := make([]byte, types.FileHeaderSize64+l.Len())
	le.PutUint32(out[0:4], uint32(types.Magic64))
	le.PutUint32(out[4:8], uint32(types.CPUArm64))
	le.PutUint32(out[12:16], uint32(types.MH_DYLIB))
	le.PutUint32(out[16:20], uint32(len(loads)))
	le.PutUint32(out[20:24], uint32(l.Len()))
	copy(out[types.FileHeaderSize64:], l.Bytes())
	return out
}

func cmdNote(offset, size uint64) []byte {
	le := binary.LittleEndian
	b := make([]byte, 8+16+16)
	le.PutUint32(b[0:4], uint32(types.LC_NOTE))
	le.PutUint32(b[4:8], uint32(len(b)))
	copy(b[8:24], "fuzzer")
	le.PutUint64(b[24:32], offset)
	le.PutUint64(b[32:40], size)
	return b
}

func cmdThread(count uint32) []byte {
	le := binary.LittleEndian
	b := make([]byte, 16)
	le.PutUint32(b[0:4], uint32(types.LC_THREAD))
	le.PutUint32(b[4:8], 16) // count*4 must fit past the header; the parser bounds it
	le.PutUint32(b[8:12], 6) // ARM_THREAD_STATE64
	le.PutUint32(b[12:16], count)
	return b
}

func cmdTwolevelHints(numHints uint32) []byte {
	le := binary.LittleEndian
	b := make([]byte, 16)
	le.PutUint32(b[0:4], uint32(types.LC_TWOLEVEL_HINTS))
	le.PutUint32(b[4:8], 16)
	le.PutUint32(b[12:16], numHints)
	return b
}

func mustReject(t *testing.T, data []byte, wantSub string) {
	t.Helper()
	_, err := NewFile(bytes.NewReader(data))
	if err == nil {
		t.Fatalf("malformed Mach-O was accepted, wanted rejection containing %q", wantSub)
	}
	if !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("rejection %q does not contain %q", err.Error(), wantSub)
	}
}

// A __z-prefixed section whose 12-byte compressed header cannot be read used

// LC_THREAD/LC_UNIXTHREAD used to multiply an untrusted count by 4 (which
// could wrap uint32) and allocate before checking the command bounds.
func TestFuzzRegressionThreadStateCountOverflow(t *testing.T) {
	mustReject(t, thinImage64(cmdThread(0x40000000)), "extends past command data")
	mustReject(t, thinImage64(cmdThread(0x100)), "extends past command data")
}

// LC_TWOLEVEL_HINTS sized its hint table from an untrusted count.
func TestFuzzRegressionTwolevelHintsCountOverflow(t *testing.T) {
	mustReject(t, thinImage64(cmdTwolevelHints(0xFFFFFFFF)), "extends past command data")
}

// A bind stream that executes DO_BIND before any segment was established
// used to nil-dereference f.Segment(bind.Segment).
func TestFuzzRegressionBindWithoutSegment(t *testing.T) {
	m, err := NewFile(bytes.NewReader(seedArm64Dylib()))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// BIND_OPCODE_DO_BIND with no preceding SET_SEGMENT_AND_OFFSET_ULEB
	_, err = m.parseBinds(bytes.NewReader([]byte{0x90}), types.BIND_KIND)
	if err == nil || !strings.Contains(err.Error(), "unknown segment") {
		t.Fatalf("got %v, wanted unknown segment error", err)
	}
}

// A malformed chained-fixups page_start with the MULTI bit set used to index
// page_start[] out of range.
func TestFuzzRegressionFixupsOverflowIndex(t *testing.T) {
	blob := fixupsSeedBlob()
	le := binary.LittleEndian
	// page_starts[0] sits after header(28) + starts_in_image(8) +
	// starts_in_segment(22); overwrite it with a MULTI start whose overflow
	// index (127) is far beyond the single-entry array
	pageStartsOff := 28 + 8 + binary.Size(fixupchains.DyldChainedStartsInSegment{})
	le.PutUint16(blob[pageStartsOff:], uint16(0x8000|0x7F))
	var mr types.MachoReader = types.NewCustomSectionReader(bytes.NewReader(nil), nil, 0, 0)
	dcf := fixupchains.NewChainedFixups(bytes.NewReader(blob), &mr, le)
	_, err := dcf.Parse()
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("got %v, wanted out-of-range error", err)
	}
}

// A cyclic export trie (a child edge pointing back at the root) used to
// recurse until the stack overflowed.
func TestFuzzRegressionTrieCycle(t *testing.T) {
	// root: terminal_size=0, children=1, edge 'a', NUL, child offset 0 (self);
	// every level re-reads the same bytes and recurses on itself
	cycle := []byte{0x00, 0x01, 'a', 0x00, 0x00}
	if _, err := trie.ParseTrieExports(bytes.NewReader(cycle), 0); err == nil {
		t.Fatal("cyclic trie was accepted")
	} else if !strings.Contains(err.Error(), "maximum depth") {
		t.Fatalf("got %v, wanted maximum depth error", err)
	}
}

// LC_NOTE used to make([]byte, size) with an untrusted uint64 size before
// validating it, panicking with "makeslice: len out of range".
func TestFuzzRegressionLCNoteHugeSize(t *testing.T) {
	mustReject(t, thinImage64(cmdNote(0, math.MaxUint64)), "failed to read Note data")
}

// An embedded LLVM bitcode bundle whose xar header declares a huge
// compressed table-of-contents used to make([]byte, toc_len) directly.
func TestFuzzRegressionXarHugeTOC(t *testing.T) {
	le := binary.LittleEndian
	// xar header: magic 'xar!', size 28, version 1, toc_len_zlib = MaxUint64
	bundle := make([]byte, 64)
	binary.BigEndian.PutUint32(bundle[0:4], 0x78617221) // "xar!"
	binary.BigEndian.PutUint16(bundle[4:6], 28)
	binary.BigEndian.PutUint16(bundle[6:8], 1)
	binary.BigEndian.PutUint64(bundle[8:16], math.MaxUint64)

	var l bytes.Buffer
	binary.Write(&l, le, types.Segment64{
		LoadCmd: types.LC_SEGMENT_64,
		Len:     72 + 80,
		Name:    to16("__LLVM"),
		Addr:    0,
		Memsz:   0x100,
		Offset:  0,
		Filesz:  0x100,
		Maxprot: 5,
		Prot:    5,
		Nsect:   1,
	})
	binary.Write(&l, le, types.Section64{
		Name: to16("__bundle"), Seg: to16("__LLVM"),
		Addr: 0x40, Size: uint64(len(bundle)),
		Offset: uint32(types.FileHeaderSize64 + 72 + 80), // right after the loads
	})

	out := append(thinImage64(l.Bytes()), bundle...)
	m, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.GetEmbeddedLLVMBitcode(); err == nil {
		t.Fatal("xar with huge TOC length was accepted")
	}
}

// A __z-prefixed section whose 12-byte compressed header cannot be read used
// to panic("Malformed object file").
// A cyclic export trie whose empty edge hops back to itself used to make
// WalkTrie loop forever (found by FuzzNewFile: worker hung 10m then died).
func TestFuzzRegressionWalkTrieCycle(t *testing.T) {
	// node@0: terminal=0, 1 child, empty edge ('\x00' matches anything),
	// child offset 4; node@4: same shape with child offset 4 (self-cycle).
	// The walk hops 0 -> 4 -> 4 -> ... forever without consuming the symbol.
	cycle := []byte{0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04}
	done := make(chan struct{})
	go func() {
		_, err := trie.WalkTrie(bytes.NewReader(cycle), "_main")
		if err == nil {
			t.Error("cyclic trie walk was accepted")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("WalkTrie hung on cyclic trie")
	}
}

// Chained-fixups metadata with a nonsense page size used to make every
// page's chain walk re-read the same window of the file (PageSize=0), a
// quadratic blowup that hung the worker for 10+ minutes (found by
// FuzzNewFile as mutation family of 08330368c946b720).
func TestFuzzRegressionFixupsInvalidPageSize(t *testing.T) {
	blob := fixupsSeedBlob()
	le := binary.LittleEndian
	// segment starts: after header(28) + starts_in_image(8); PageSize at offset 4
	segOff := 28 + 8
	le.PutUint16(blob[segOff+4:], 0) // PageSize = 0
	var mr types.MachoReader = types.NewCustomSectionReader(bytes.NewReader(nil), nil, 0, 0)
	dcf := fixupchains.NewChainedFixups(bytes.NewReader(blob), &mr, le)
	_, err := dcf.Parse()
	if err == nil || !strings.Contains(err.Error(), "invalid page size") {
		t.Fatalf("got %v, wanted invalid page size error", err)
	}
}

// A fixups header claiming billions of imports used to size a multi-GB
// allocation before any data check (worker OOM/timeout: mutation family of
// 4682d19f404e4ecb, seed found-ce52b1dfee28ffed).
func TestFuzzRegressionFixupsImportCount(t *testing.T) {
	blob := fixupsSeedBlob()
	le := binary.LittleEndian
	// header: FixupsVersion(4) StartsOffset(4) ImportsOffset(4) SymbolsOffset(4)
	// ImportsCount(4) at offset 16 — claim 4 billion entries
	le.PutUint32(blob[16:20], 0xFFFFFFFF)
	var mr types.MachoReader = types.NewCustomSectionReader(bytes.NewReader(nil), nil, 0, 0)
	dcf := fixupchains.NewChainedFixups(bytes.NewReader(blob), &mr, le)
	_, err := dcf.Parse()
	if err == nil || !strings.Contains(err.Error(), "imports count") {
		t.Fatalf("got %v, wanted imports count error", err)
	}
}

// An MH_FILESET whose LC_FILESET_ENTRY offset points back at its own header
// used to recurse FindSectionForVMAddr -> GetFileSetFileByName -> NewFile
// forever (self-nesting filesets do not exist in dyld).
func TestFuzzRegressionFilesetSelfReference(t *testing.T) {
	le := binary.LittleEndian
	entryID := "self\x00"
	var segCmd, fsCmd bytes.Buffer
	binary.Write(&segCmd, le, types.Segment64{
		LoadCmd: types.LC_SEGMENT_64,
		Len:     72,
		Name:    to16("__TEXT"),
		Addr:    0,
		Memsz:   0x1000,
		Offset:  0,
		Filesz:  0x1000,
		Maxprot: 5,
		Prot:    5,
	})
	binary.Write(&fsCmd, le, types.FilesetEntryCmd{
		LoadCmd:       types.LC_FILESET_ENTRY,
		Len:           uint32(32 + len(entryID)),
		Addr:          0x1000,
		FileOffset:    0, // points at this file's own header
		EntryIdOffset: 32,
	})
	fsCmd.WriteString(entryID)

	// hand-assemble the header: MH_FILESET type
	loads := append(append([]byte(nil), segCmd.Bytes()...), fsCmd.Bytes()...)
	out := make([]byte, types.FileHeaderSize64+len(loads))
	le.PutUint32(out[0:4], uint32(types.Magic64))
	le.PutUint32(out[4:8], uint32(types.CPUArm64))
	le.PutUint32(out[12:16], uint32(types.MH_FILESET))
	le.PutUint32(out[16:20], 2)
	le.PutUint32(out[20:24], uint32(len(loads)))
	copy(out[types.FileHeaderSize64:], loads)

	m, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// this used to recurse forever through the self-referencing entry
		if sec := m.FindSectionForVMAddr(0x100400088); sec != nil {
			t.Error("section found in cyclic fileset")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("FindSectionForVMAddr hung on cyclic fileset")
	}
}

func TestFuzzRegressionZSectionHeaderShort(t *testing.T) {
	le := binary.LittleEndian
	seg := types.Segment64{
		LoadCmd: types.LC_SEGMENT_64,
		Len:     72 + 80,
		Name:    to16("__TEXT"),
		Addr:    0,
		Memsz:   0x100,
		Offset:  0,
		Filesz:  0x100,
		Maxprot: 5,
		Prot:    5,
		Nsect:   1,
	}
	sect := types.Section64{Name: to16("__zdebug_info"), Seg: to16("__TEXT"), Addr: 0x40, Size: 0, Offset: 0x40}
	var l bytes.Buffer
	binary.Write(&l, le, seg)
	binary.Write(&l, le, sect)
	m, err := NewFile(bytes.NewReader(thinImage64(l.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if len(m.Sections) == 0 {
		t.Fatal("section missing")
	}
	if _, err := m.Sections[0].UncompressedSize(); err == nil {
		t.Fatal("short __z section was accepted")
	}
}

// TestFuzzRegressionRebaseSkipWrapHang reproduces a hang found while fuzzing
// FuzzNewFile: REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB with
// skip = 2^64 - pointerSize makes rebase.Offset += skip + pointerSize wrap
// back to the same value, so the loop re-reads the same in-bounds slot and
// appends forever (100% CPU + unbounded memory).
func TestFuzzRegressionRebaseSkipWrapHang(t *testing.T) {
	le := binary.LittleEndian

	// rebase stream: set segment 0 offset 0; then DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
	// with count = MaxUint64 and skip = MaxUint64-7 (skip+8 wraps to 0)
	var stream bytes.Buffer
	stream.WriteByte(types.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 0) // imm 0
	trie.EncodeUleb128(&stream, 0)                                        // segment offset 0
	stream.WriteByte(types.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB)
	trie.EncodeUleb128(&stream, ^uint64(0)) // count: MaxUint64
	trie.EncodeUleb128(&stream, ^uint64(7)) // skip: 2^64-8; skip+8 == 0 (mod 2^64)
	rebaseData := stream.Bytes()

	var segCmd, infoCmd bytes.Buffer
	binary.Write(&segCmd, le, types.Segment64{
		LoadCmd: types.LC_SEGMENT_64,
		Len:     72,
		Name:    to16("__TEXT"),
		Addr:    0,
		Memsz:   0x100,
		Offset:  0,
		Filesz:  0x100,
		Maxprot: 5,
		Prot:    5,
	})
	binary.Write(&infoCmd, le, types.DyldInfoOnlyCmd{
		LoadCmd:    types.LC_DYLD_INFO_ONLY,
		Len:        48,
		RebaseOff:  uint32(types.FileHeaderSize64 + 72 + 48),
		RebaseSize: uint32(len(rebaseData)),
	})

	out := append(thinImage64(segCmd.Bytes(), infoCmd.Bytes()), rebaseData...)
	m, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if _, err := m.GetRebaseInfo(); err == nil {
		t.Fatal("wrap-around rebase stream was accepted")
	}
}
