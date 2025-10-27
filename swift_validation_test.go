package macho

import (
	"testing"
)

// TestIsValidSwiftTypeName tests the validation of Swift type names
func TestIsValidSwiftTypeName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid Swift type",
			input:    "MyClass",
			expected: true,
		},
		{
			name:     "valid module name",
			input:    "Foundation",
			expected: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "objc_release symbol",
			input:    "_objc_release",
			expected: false,
		},
		{
			name:     "objc_release with register",
			input:    "_objc_release_x19",
			expected: false,
		},
		{
			name:     "objc_retain symbol",
			input:    "objc_retain",
			expected: false,
		},
		{
			name:     "swift runtime symbol",
			input:    "_swift_allocObject",
			expected: false,
		},
		{
			name:     "register spill symbol",
			input:    "something_x19",
			expected: false,
		},
		{
			name:     "register spill single digit",
			input:    "foo_x9",
			expected: false,
		},
		{
			name:     "valid name with x in middle",
			input:    "MyClassExtension",
			expected: true,
		},
		{
			name:     "valid name ending with x",
			input:    "Matrix",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSwiftTypeName(tt.input)
			if result != tt.expected {
				t.Errorf("isValidSwiftTypeName(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestContainsNonPrintable tests detection of non-printable characters
func TestContainsNonPrintable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "normal ASCII",
			input:    "Swift.Bool",
			expected: false,
		},
		{
			name:     "with spaces",
			input:    "Swift Array",
			expected: false,
		},
		{
			name:     "with tab",
			input:    "Swift\tArray",
			expected: false,
		},
		{
			name:     "with newline",
			input:    "Swift\nArray",
			expected: false,
		},
		{
			name:     "replacement character",
			input:    "Swift\uFFFDArray",
			expected: true,
		},
		{
			name:     "control character",
			input:    "Swift\x01Array",
			expected: true,
		},
		{
			name:     "null byte",
			input:    "Swift\x00Array",
			expected: true,
		},
		{
			name:     "bell character",
			input:    "Swift\x07Array",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsNonPrintable(tt.input)
			if result != tt.expected {
				t.Errorf("containsNonPrintable(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestFormatSwiftTypeNameWithNonPrintable tests that formatSwiftTypeName
// returns the raw mangling when the demangled result contains non-printable characters
func TestFormatSwiftTypeNameWithNonPrintable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantRaw  bool // true if we expect the raw input back
	}{
		{
			name:    "valid mangling with prefix",
			input:   "_$sSb",
			wantRaw: false, // Should demangle successfully
		},
		{
			name:    "bare type without prefix returns raw",
			input:   "Sb",
			wantRaw: false, // Bare types are now treated as fragments and demangled
		},
		{
			name:    "invalid mangling returns raw",
			input:   "_objc_release_x19",
			wantRaw: true, // Should return raw because it won't demangle
		},
		{
			name:    "garbage returns raw",
			input:   "\x01\xa3\x06",
			wantRaw: true, // Should return raw because demangling would fail or produce garbage
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSwiftTypeName(tt.input)

			if tt.wantRaw {
				// Should get the raw input back
				if result != tt.input {
					t.Errorf("formatSwiftTypeName(%q) = %q, want raw input %q", tt.input, result, tt.input)
				}
			} else {
				// Should get something different (demangled)
				if result == tt.input {
					t.Errorf("formatSwiftTypeName(%q) returned raw input, expected demangled output", tt.input)
				}
				// And it shouldn't contain non-printable characters
				if containsNonPrintable(result) {
					t.Errorf("formatSwiftTypeName(%q) = %q contains non-printable characters", tt.input, result)
				}
			}
		})
	}
}

// TestIsPrintableASCII tests the helper function for checking printable ASCII
func TestIsPrintableASCII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "simple ASCII",
			input:    "HelloWorld",
			expected: true,
		},
		{
			name:     "with spaces",
			input:    "Hello World",
			expected: true,
		},
		{
			name:     "with punctuation",
			input:    "Hello, World!",
			expected: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false, // Empty string returns false
		},
		{
			name:     "with control character",
			input:    "Hello\x01World",
			expected: false,
		},
		{
			name:     "with high byte",
			input:    "Hello\xFFWorld",
			expected: false,
		},
		{
			name:     "mangled symbol",
			input:    "_$s4TestAAC",
			expected: true, // Mangled symbols are ASCII
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrintableASCII(tt.input)
			if result != tt.expected {
				t.Errorf("isPrintableASCII(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
