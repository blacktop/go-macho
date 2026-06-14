package swift

import "testing"

func TestBlobTokenPattern(t *testing.T) {
	matches := blobTokenPattern.FindAllString("foo _$s16DemangleFoo $sSS7cString So8NSStringC _T012Something _$es16_emptyBoxStorageSi_Sitvp", -1)
	want := []string{"_$s16DemangleFoo", "$sSS7cString", "So8NSStringC", "_T012Something", "_$es16_emptyBoxStorageSi_Sitvp"}
	if len(matches) != len(want) {
		t.Fatalf("got %d matches, want %d", len(matches), len(want))
	}
	for i := range want {
		if matches[i] != want[i] {
			t.Fatalf("match[%d]=%q want %q", i, matches[i], want[i])
		}
	}
}

func TestIsMangled(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"_$s16DemangleFoo", true},
		{"$sSS7cString", true},
		{"_$S4main", true},
		{"_$es16_emptyBoxStorageSi_Sitvp", true}, // Embedded Swift
		{"$e4main", true},
		{"_T012Something", true},
		{"_swift_retain", false},
		{"__ZN3foo3barEv", false},
		{"", false},
	} {
		if got := IsMangled(tc.in); got != tc.want {
			t.Errorf("IsMangled(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
