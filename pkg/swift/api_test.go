package swift

import "testing"

func TestBlobTokenPattern(t *testing.T) {
	matches := blobTokenPattern.FindAllString("foo _$s16DemangleFoo $sSS7cString So8NSStringC _T012Something", -1)
	want := []string{"_$s16DemangleFoo", "$sSS7cString", "So8NSStringC", "_T012Something"}
	if len(matches) != len(want) {
		t.Fatalf("got %d matches, want %d", len(matches), len(want))
	}
	for i := range want {
		if matches[i] != want[i] {
			t.Fatalf("match[%d]=%q want %q", i, matches[i], want[i])
		}
	}
}
