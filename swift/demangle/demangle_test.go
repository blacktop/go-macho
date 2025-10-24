package demangle

import (
	"testing"
)

func TestNormalizeIdentifierTuples(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{name: "BasicTuple", in: "Si_SSt", out: "(Swift.Int, Swift.String)"},
		{name: "OptionalTuple", in: "Si_SStSg", out: "(Swift.Int, Swift.String)?"},
		{name: "Optional", in: "_$sSSSg", out: "Swift.String?"},
	}

	for _, tc := range cases {
		got := NormalizeIdentifier(tc.in)
		if got != tc.out {
			t.Fatalf("%s: NormalizeIdentifier(%q) = %q, want %q", tc.name, tc.in, got, tc.out)
		}
	}
}

func TestNormalizeIdentifierSymbol(t *testing.T) {
	in := "func _$s13lockdownmoded18LockdownModeServerC8listener_25shouldAcceptNewConnectionSbSo13NSXPCListenerC_So15NSXPCConnectionCtF"
	got := NormalizeIdentifier(in)
	want := "func lockdownmoded.LockdownModeServer.listener(_: __C.NSXPCListener, shouldAcceptNewConnection: __C.NSXPCConnection) -> Swift.Bool"
	if got != want {
		t.Fatalf("NormalizeIdentifier(%q) = %q, want %q", in, got, want)
	}
}
