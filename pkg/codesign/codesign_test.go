package codesign

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/pkg/codesign/types"
)

// embeddedSignature wraps one CSSLOT_REQUIREMENTS blob in an embedded-signature SuperBlob.
func embeddedSignature(t *testing.T, requirementsHex string) []byte {
	t.Helper()
	reqs, err := hex.DecodeString(requirementsHex)
	if err != nil {
		t.Fatalf("decode requirements fixture: %v", err)
	}
	const headerLen = 12 + 8 // SuperBlob header + one BlobIndex
	sig := binary.BigEndian.AppendUint32(nil, uint32(types.MAGIC_EMBEDDED_SIGNATURE))
	sig = binary.BigEndian.AppendUint32(sig, uint32(headerLen+len(reqs)))
	sig = binary.BigEndian.AppendUint32(sig, 1)
	sig = binary.BigEndian.AppendUint32(sig, uint32(types.CSSLOT_REQUIREMENTS))
	sig = binary.BigEndian.AppendUint32(sig, headerLen)
	return append(sig, reqs...)
}

// Requirements blobs are copied from `codesign -f -s - -r='<type> => ...' <macho>`.
// want matches `codesign -d -r-`, except go-macho omits "designated => " and quotes identifiers.
func TestParseCodeSignatureRequirementTypes(t *testing.T) {
	tests := []struct {
		name         string
		requirements string
		want         string
		wantErr      string
	}{
		{
			name:         "designated",
			requirements: "fade0c010000002c000000010000000300000014fade0c000000001800000001000000020000000161000000",
			want:         `identifier "a"`,
		},
		{
			name:         "host",
			requirements: "fade0c0100000024000000010000000100000014fade0c00000000100000000100000003",
			want:         "host => anchor apple",
		},
		{
			name:         "guest",
			requirements: "fade0c0100000024000000010000000200000014fade0c00000000100000000100000003",
			want:         "guest => anchor apple",
		},
		{
			name:         "library",
			requirements: "fade0c0100000024000000010000000400000014fade0c00000000100000000100000003",
			want:         "library => anchor apple",
		},
		{
			name:         "plugin",
			requirements: "fade0c0100000024000000010000000500000014fade0c00000000100000000100000003",
			want:         "plugin => anchor apple",
		},
		{
			name:         "unknown type",
			requirements: "fade0c0100000024000000010000000600000014fade0c00000000100000000100000003",
			wantErr:      "unsupported codesign requirement type 'RequirementType(6)'",
		},
		{
			// The expression ends two bytes into a second opcode; the type is
			// rejected before the body is read.
			name:         "unknown type with malformed body",
			requirements: "fade0c0100000026000000010000000600000014fade0c00000000120000000100000003" + "0000",
			wantErr:      "unsupported codesign requirement type 'RequirementType(6)'",
		},
		{
			name:         "identifier length past the end",
			requirements: "fade0c010000002c000000010000000300000014fade0c00000000180000000100000002ffffffff00000000",
			wantErr:      "requirement data length 4294967295 exceeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs, err := ParseCodeSignature(embeddedSignature(t, tt.requirements))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseCodeSignature() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCodeSignature() error = %v", err)
			}
			if len(cs.Requirements) != 1 {
				t.Fatalf("len(Requirements) = %d, want 1", len(cs.Requirements))
			}
			if got := cs.Requirements[0].Detail; got != tt.want {
				t.Errorf("Requirements[0].Detail = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSignRejectsConstraintSlots(t *testing.T) {
	config := &Config{
		ID:           "com.example.hello",
		Flags:        types.ADHOC,
		SpecialSlots: make([]types.SpecialSlot, int(types.CSSLOT_LAUNCH_CONSTRAINT_PARENT)),
	}
	if _, err := Sign(bytes.NewReader(nil), config); err == nil {
		t.Fatal("Sign() accepted a code directory with launch constraint slots")
	}
}

func TestSignRejectsWrongLengthSlotHash(t *testing.T) {
	config := &Config{ID: "com.example.hello", Flags: types.ADHOC}
	config.InitSlotHashes()
	config.SlotHashes.ResourceDir = bytes.Repeat([]byte{1}, 20) // SHA-1 sized
	_, err := Sign(bytes.NewReader(nil), config)
	if err == nil || !strings.Contains(err.Error(), "special slot 3 (Resource Directory) hash is 20 bytes") {
		t.Fatalf("Sign() error = %v, want the 20-byte resource directory hash rejected", err)
	}
}

func TestSignKeepsResourceDirWhenReusingSlots(t *testing.T) {
	rsrc := bytes.Repeat([]byte{1}, 32)
	config := &Config{
		ID:           "com.example.hello",
		Flags:        types.ADHOC,
		SpecialSlots: make([]types.SpecialSlot, 2), // from a previous 2-slot signature
	}
	config.InitSlotHashes()
	config.SlotHashes.ResourceDir = rsrc
	sig, err := Sign(bytes.NewReader(nil), config)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	cs, err := ParseCodeSignature(sig)
	if err != nil {
		t.Fatalf("ParseCodeSignature() error = %v", err)
	}
	slots := cs.CodeDirectories[0].SpecialSlots
	if len(slots) != 3 || !bytes.Equal(slots[0].Hash, rsrc) {
		t.Fatalf("special slots = %+v, want 3 with the resource directory hash in slot 3", slots)
	}
}

func TestSignReusesFiveSlotSignature(t *testing.T) {
	const ents = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>`
	sign := func(previous []types.SpecialSlot) []types.SpecialSlot {
		t.Helper()
		config := &Config{ID: "com.example.hello", Flags: types.ADHOC, Entitlements: []byte(ents), SpecialSlots: previous}
		config.InitSlotHashes()
		sig, err := Sign(bytes.NewReader(nil), config)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		cs, err := ParseCodeSignature(sig)
		if err != nil {
			t.Fatalf("ParseCodeSignature() error = %v", err)
		}
		return cs.CodeDirectories[0].SpecialSlots
	}
	first := sign(nil)
	second := sign(first)
	if len(second) != 5 || !bytes.Equal(second[0].Hash, first[0].Hash) {
		t.Fatalf("re-signed special slots = %+v, want the 5 slots of %+v", second, first)
	}
}

func TestSignComparesPreviousInfoPlist(t *testing.T) {
	tests := []struct {
		name    string
		slot1   []byte
		wantErr bool
	}{
		{name: "unbound", slot1: make([]byte, 32)},
		{name: "different bound hash", slot1: bytes.Repeat([]byte{1}, 32), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ID:        "com.example.hello",
				Flags:     types.ADHOC,
				InfoPlist: []byte(`<plist version="1.0"><dict/></plist>`),
				SpecialSlots: []types.SpecialSlot{
					{Index: uint32(types.CSSLOT_REQUIREMENTS), Hash: types.EmptySha256ReqSlot},
					{Index: uint32(types.CSSLOT_INFOSLOT), Hash: tt.slot1},
				},
			}
			config.InitSlotHashes()
			if _, err := Sign(bytes.NewReader(nil), config); (err != nil) != tt.wantErr {
				t.Fatalf("Sign() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
