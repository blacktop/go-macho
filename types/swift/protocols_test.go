package swift

import "testing"

func TestInvertibleProtocolSet_String(t *testing.T) {
	tests := []struct {
		name string
		set  InvertibleProtocolSet
		want string
	}{
		{name: "empty", set: 0, want: "InvertibleProtocolSet(0x0)"},
		{name: "copyable", set: InvertibleProtocolCopyable, want: "~Copyable"},
		{name: "escapable", set: InvertibleProtocolEscapable, want: "~Escapable"},
		{
			name: "copyable and escapable",
			set:  InvertibleProtocolCopyable | InvertibleProtocolEscapable,
			want: "~Copyable & ~Escapable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.set.String(); got != tt.want {
				t.Errorf("InvertibleProtocolSet(0x%x).String() = %q, want %q", uint16(tt.set), got, tt.want)
			}
		})
	}
}

// TestInvertibleProtocolSet_FromPayload documents the GRKindInvertedProtocols
// payload encoding: the suppressed-protocol bitset lives in the high 16 bits of
// the requirement's payload word, while the low 16 bits hold the generic
// parameter index (which the requirement parsers discard).
func TestInvertibleProtocolSet_FromPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload int32 // mirrors the signed TargetGenericRequirementDescriptor RelOff
		want    string
	}{
		{name: "copyable", payload: 0x0001_0000, want: "~Copyable"},
		{name: "escapable", payload: 0x0002_0000, want: "~Escapable"},
		{name: "copyable and escapable", payload: 0x0003_0000, want: "~Copyable & ~Escapable"},
		{name: "param index in low bits is ignored", payload: 0x0003_abcd, want: "~Copyable & ~Escapable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InvertibleProtocolSet(uint32(tt.payload) >> 16).String()
			if got != tt.want {
				t.Errorf("payload 0x%08x decoded to %q, want %q", uint32(tt.payload), got, tt.want)
			}
		})
	}
}

func TestGenericRequirementKind_String(t *testing.T) {
	tests := []struct {
		name string
		kind GenericRequirementKind
		want string
	}{
		{name: "protocol", kind: GRKindProtocol, want: "protocol"},
		{name: "same-shape", kind: GRKSameShape, want: "same-shape"},
		{name: "inverted-protocols", kind: GRKindInvertedProtocols, want: "inverted-protocols"},
		{name: "layout", kind: GRKindLayout, want: "layout"},
		{name: "unknown", kind: GenericRequirementKind(6), want: "GenericRequirementKind(6)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("GenericRequirementKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}
