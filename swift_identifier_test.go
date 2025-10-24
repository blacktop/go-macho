package macho

import (
	"strings"
	"testing"

	"github.com/blacktop/go-macho/internal/swiftdemangle"
	"github.com/blacktop/go-macho/swift/demangle"
)

func TestNormalizeIdentifier(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{name: "ProtocolComposition", in: "_$ss5ErrorMp", out: "Swift.Error"},
		{name: "ObjCBool", in: "$s10ObjectiveC8ObjCBoolVMn", out: "ObjectiveC.ObjCBool"},
		{name: "OptionalString", in: "$sSSSg", out: "Swift.String?"},
		{name: "ArrayInt", in: "_$sSaySiG", out: "[Swift.Int]"},
		{name: "Dictionary", in: "_$sSDySSSiG", out: "[Swift.String : Swift.Int]"},
		{name: "Tuple", in: "Si_SSt", out: "(Swift.Int, Swift.String)"},
		{name: "OptionalTuple", in: "Si_SStSg", out: "(Swift.Int, Swift.String)?"},
		{name: "PlainASCII", in: "lockdownmoded.LockdownModeServer", out: "lockdownmoded.LockdownModeServer"},
	}

	for _, tc := range cases {
		mangled := strings.TrimPrefix(tc.in, "_")
		if out, _, err := swiftdemangle.New(nil).DemangleString([]byte(mangled)); err != nil {
			t.Logf("direct demangle of %q failed: %v", tc.in, err)
		} else {
			t.Logf("direct demangle of %q => %q", tc.in, out)
		}

		got := demangle.NormalizeIdentifier(tc.in)
		if got != tc.out {
			t.Fatalf("%s: demangle.NormalizeIdentifier(%q) = %q, want %q", tc.name, tc.in, got, tc.out)
		}
	}
}

func TestNormalizeIdentifierUnknown(t *testing.T) {
	// Unknown tokens should be returned unchanged so callers can decide how to display them.
	const token = "$s__mystery__"
	if got := demangle.NormalizeIdentifier(token); got != token {
		t.Fatalf("demangle.NormalizeIdentifier(%q) = %q, want original", token, got)
	}
}
