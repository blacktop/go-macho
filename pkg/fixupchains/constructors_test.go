package fixupchains

import "testing"

func TestArm64eConstructorsRoundTrip(t *testing.T) {
	rebase := NewDyldChainedPtrArm64eRebase(0x10, 0xfe00000001234567, 3)
	if rebase.Offset() != 0x10 || rebase.Target() != 0x1234567 || rebase.High8() != 0xfe || rebase.Next() != 3 || rebase.Bind() != 0 || rebase.Auth() != 0 {
		t.Errorf("rebase decodes as %s", rebase.String())
	}

	bind, err := NewDyldChainedPtrArm64eBind(0x18, 7, -4, 2, "_foo")
	if err != nil {
		t.Fatal(err)
	}
	if bind.Ordinal() != 7 || bind.SignExtendedAddend() != -4 || bind.Next() != 2 || bind.Bind() != 1 || bind.Auth() != 0 || bind.Name() != "_foo" {
		t.Errorf("bind decodes as %s", bind.String())
	}
	if _, err := NewDyldChainedPtrArm64eBind(0, 0, 1<<18, 0, "_foo"); err == nil {
		t.Error("expected an error for an addend outside the 19-bit range")
	}

	authRebase := NewDyldChainedPtrArm64eAuthRebase(0x20, 0x4000, 0x1234, 1, 2, 5)
	if authRebase.Target() != 0x4000 || authRebase.Diversity() != 0x1234 || authRebase.AddrDiv() != 1 || authRebase.Key() != 2 || authRebase.Next() != 5 || authRebase.Bind() != 0 || authRebase.Auth() != 1 {
		t.Errorf("auth rebase decodes as %s", authRebase.String())
	}

	authBind := NewDyldChainedPtrArm64eAuthBind(0x28, 9, 0xbeef, 0, 1, 1, "_bar")
	if authBind.Ordinal() != 9 || authBind.Diversity() != 0xbeef || authBind.AddrDiv() != 0 || authBind.Key() != 1 || authBind.Next() != 1 || authBind.Bind() != 1 || authBind.Auth() != 1 || authBind.Name() != "_bar" {
		t.Errorf("auth bind decodes as %s", authBind.String())
	}

	header := DyldChainedFixupsHeader{FixupsVersion: 0, StartsOffset: 0x20, ImportsOffset: 0x40, SymbolsOffset: 0x50, ImportsCount: 2, ImportsFormat: DC_IMPORT, SymbolsFormat: 0}
	data := header.Data()
	if len(data) != 28 || data[4] != 0x20 || data[8] != 0x40 || data[12] != 0x50 || data[16] != 2 || data[20] != byte(DC_IMPORT) {
		t.Errorf("header data = % x", data)
	}
}
