package swift

import "testing"

func TestLooksLikeSwiftSymbol(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"_$s16DemangleFixtures7CounterC5valueSivg", true},
		{"$sSaySiG", true},
		{"So8NSStringC", true},
		{"_$sSo8NSStringC", true},
		{"_T012LockdownModeServerC", true},
		{"lockdownmoded.LockdownModeServer", false},
		{"", false},
		{"??", false},
		{"NSObject", false},
	}
	for _, tc := range cases {
		if got := looksLikeSwiftSymbol(tc.in); got != tc.want {
			t.Fatalf("looksLikeSwiftSymbol(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestPureGoEnginePassThrough(t *testing.T) {
	eng := pureGoEngine{}
	input := "lockdownmoded.LockdownModeServer"
	got, err := eng.Demangle(input)
	if err != nil {
		t.Fatalf("Demangle returned error: %v", err)
	}
	if got != input {
		t.Fatalf("Demangle(%q) = %q, want unchanged", input, got)
	}
}
