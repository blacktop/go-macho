package types

import (
	"fmt"
	"testing"
)

func TestExportFlagPredicates(t *testing.T) {
	for _, tc := range []struct {
		flags                            ExportFlag
		weak, reexport, resolver, static bool
	}{
		{0x00, false, false, false, false},
		{0x04, true, false, false, false},
		{0x08, false, true, false, false},
		{0x0c, true, true, false, false},
		{0x10, false, false, true, false},
		{0x14, true, false, true, false},
		{0x20, false, false, false, true},
		{0x24, true, false, false, true},
		{0x3c, true, true, true, true},
	} {
		// Kind bits and an unknown high bit must not affect the attributes.
		for _, extra := range []ExportFlag{0, 1, 2, 3, 0x80} {
			flags := tc.flags | extra
			t.Run(fmt.Sprintf("%#x", int(flags)), func(t *testing.T) {
				got := [4]bool{flags.WeakDefinition(), flags.ReExport(), flags.StubAndResolver(), flags.StaticResolver()}
				want := [4]bool{tc.weak, tc.reexport, tc.resolver, tc.static}
				if got != want {
					t.Errorf("predicates = %v, want %v", got, want)
				}
				if flags.Regular() != (extra&3 == 0) || flags.ThreadLocal() != (extra&3 == 1) || flags.Absolute() != (extra&3 == 2) {
					t.Errorf("kind predicates changed for %#x", int(flags))
				}
			})
		}
	}
}

func TestExportFlagString(t *testing.T) {
	for _, tc := range []struct {
		flags ExportFlag
		want  string
	}{
		{0x00, "regular"},
		{0x01, "per-thread"},
		{0x02, "absolute"},
		{0x04, "regular|weak_def"},
		{0x08, "regular"},
		{0x10, "regular|has_resolver"},
		{0x20, "regular|static_resolver"},
		{0x0c, "regular|weak_def|[re-export]"},
		{0x14, "regular|has_resolver|weak_def"},
		{0x24, "regular|static_resolver|weak_def"},
		{0x34, "regular|has_resolver|static_resolver|weak_def"},
	} {
		t.Run(fmt.Sprintf("%#x", int(tc.flags)), func(t *testing.T) {
			if got := tc.flags.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}
