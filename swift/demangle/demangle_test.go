package demangle

import (
	"strings"
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
	if !strings.HasPrefix(got, "func ") {
		t.Fatalf("NormalizeIdentifier(%q) = %q, want func prefix", in, got)
	}
	if !strings.Contains(got, "LockdownModeServer.listener") {
		t.Fatalf("NormalizeIdentifier(%q) = %q, want listener symbol", in, got)
	}
}
