package types

import "testing"

func TestArm64SubtypeTaxonomy(t *testing.T) {
	if CPUSubtypeArm64X1 != 3 || CPUSubtypeArm64EX1 != 12 || CPUSubtypeArm64Max != 20 {
		t.Fatal("ARM64 subtype constants differ from the supplied header")
	}
	for base := CPUSubtype(0); base <= 21; base++ {
		for flags := uint32(0); flags <= 255; flags++ {
			st := base | CPUSubtype(flags<<24)
			if got, want := st.HasArm64E(), base == 2 || base == 12; got != want {
				t.Errorf("%#x HasArm64E = %v, want %v", uint32(st), got, want)
			}
			if got, want := st.HasArm64X1(), base == 3 || base == 12; got != want {
				t.Errorf("%#x HasArm64X1 = %v, want %v", uint32(st), got, want)
			}
		}
	}
}

func TestArm64X1Formatting(t *testing.T) {
	for _, tt := range []struct {
		subtype    CPUSubtype
		name, caps string
	}{
		{3, "ARM64_X1", ""},
		{12, "ARM64e_X1", ""},
		{0x8100000c, "ARM64e_X1", "USR01"},
		{0xe100000c, "ARM64e_X1", "KER33"},
		{0xa1000003, "ARM64_X1", "USR01"},
	} {
		if got := tt.subtype.String(CPUArm64); got != tt.name {
			t.Errorf("String = %q, want %q", got, tt.name)
		}
		if got := tt.subtype.GoString(CPUArm64); got != "macho."+tt.name {
			t.Errorf("GoString = %q, want %q", got, "macho."+tt.name)
		}
		if got := tt.subtype.Capabilities(CPUArm64); got != tt.caps {
			t.Errorf("Capabilities = %q, want %q", got, tt.caps)
		}
	}
}

func TestArm6432Formatting(t *testing.T) {
	for _, tt := range []struct {
		subtype      CPUSubtype
		name, goName string
	}{
		{0, "ARM64_32", "macho.ARM64_32"},
		{1, "v8", "macho.v8"},
		{2, "0x2", "0x2"},
		{3, "0x3", "0x3"},
		{12, "0xc", "0xc"},
		{0x8100000c, "0xc", "0xc"},
	} {
		if got := tt.subtype.String(CPUArm6432); got != tt.name {
			t.Errorf("String(%#x) = %q, want %q", uint32(tt.subtype), got, tt.name)
		}
		if got := tt.subtype.GoString(CPUArm6432); got != tt.goName {
			t.Errorf("GoString(%#x) = %q, want %q", uint32(tt.subtype), got, tt.goName)
		}
		if got := tt.subtype.Capabilities(CPUArm6432); got != "" {
			t.Errorf("ARM64_32 capabilities = %q", got)
		}
	}
}
