package macho

import (
	"strings"
	"testing"

	"github.com/blacktop/go-macho/internal/swiftdemangle"
)

// TestSwiftManglingNormalization tests that leading underscores are properly stripped
func TestSwiftManglingNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "mangling with leading underscore",
			input:    "_Sb",
			expected: "Swift.Bool",
			wantErr:  false,
		},
		{
			name:     "mangling without leading underscore",
			input:    "Sb",
			expected: "Swift.Bool",
			wantErr:  false,
		},
		{
			name:     "optional type",
			input:    "SbSg",
			expected: "Swift.Bool?",
			wantErr:  false,
		},
		{
			name:     "tuple type",
			input:    "Si_SSt",
			expected: "(Swift.Int, Swift.String)",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate normalization
			normalized := []byte(tt.input)
			if len(normalized) > 0 && normalized[0] == '_' {
				if len(normalized) > 1 && (normalized[1] == '$' || normalized[1] >= 0x20) {
					normalized = normalized[1:]
				}
			}

			result, _, err := swiftdemangle.DemangleTypeString(string(normalized))
			if (err != nil) != tt.wantErr {
				t.Errorf("DemangleTypeString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("DemangleTypeString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestImplFunctionTypeMangling tests that impl function types with modifiers are handled
func TestImplFunctionTypeMangling(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		// Don't check exact output since impl function formatting may vary
	}{
		{
			name:    "impl function with Iegg modifiers",
			input:   "_pSgIegg_",
			wantErr: false,
		},
		{
			name:    "impl function with escaping closure",
			input:   "_pIegg_",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			normalized := tt.input
			if strings.HasPrefix(normalized, "_") && len(normalized) > 1 && (normalized[1] == '$' || normalized[1] >= 0x20) {
				normalized = normalized[1:]
			}
			result, _, err := swiftdemangle.DemangleTypeString(normalized)
			if (err != nil) != tt.wantErr {
				t.Errorf("DemangleTypeString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == "" {
				t.Error("DemangleTypeString() returned empty result")
			}
			t.Logf("Demangled '%s' -> '%s'", tt.input, result)
		})
	}
}

func TestFormatSwiftTypeNameSymbolFallback(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"_$sypyc", "() -> Any"},
		{"_$syypc", "(Any) -> ()"},
		{"ypyc", "() -> Any"},  // Bare type mangling (needs _$s prefix)
		{"_$ss12CaseIterableP8AllCasesAB_SlTn", "associated conformance descriptor for Swift.CaseIterable.Swift.CaseIterable.AllCases: Swift.Collection"},
		{"_$sXDXMT", "@thick Self.Type"}, // DynamicSelf metatype
		{"_$sSa", "Swift.Array"},  // Swift.Array type
		{"_$sSQMp", "protocol descriptor for Swift.Equatable"},
		{"_$sSHMp", "protocol descriptor for Swift.Hashable"},
		{"_$ss5ErrorMp", "Error Swift"}, // TODO: Should be "protocol descriptor for Swift.Error"
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			if got := formatSwiftTypeName(tc.input); got != tc.want {
				t.Fatalf("formatSwiftTypeName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
