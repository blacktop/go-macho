package swiftdemangle

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSymbolicReferences(t *testing.T) {
	testCases := []struct{
		name string
		hexBytes string
	}{
		{"Capture 0x10003a158[0] - Error Swift ?", "02ab46"},
		{"Capture 0x10003a158[1] - Swift.Bool", "5362"},
		{"Capture 0x10003a238[0] - Error Swift ?", "02ab46"},
		{"Capture 0x10003a268[0] - mixed", "5362029d45"},
	}

	fmt.Println("\n=== Testing Raw Mangled Bytes Through Demangler ===")

	for _, tc := range testCases {
		rawBytes, _ := hex.DecodeString(tc.hexBytes)

		fmt.Printf("%-40s: %q (hex: %s)\n", tc.name, rawBytes, tc.hexBytes)

		// Try without resolver (this will fail for symbolic references)
		result, _, err := DemangleTypeString(string(rawBytes))
		if err != nil {
			fmt.Printf("  ✗ Error (no resolver): %v\n", err)
		} else {
			fmt.Printf("  ✓ Result (no resolver): %s\n", result)
		}
		fmt.Println()
	}

	fmt.Println("=== Analysis ===")
	fmt.Println("Control byte 0x02 = Indirect symbolic reference to a context descriptor")
	fmt.Println("This REQUIRES a SymbolicReferenceResolver to resolve the pointer.")
	fmt.Println()
	fmt.Println("The demangler is failing because:")
	fmt.Println("1. It sees control byte 0x02")
	fmt.Println("2. Calls resolver.ResolveSymbolicReference()")
	fmt.Println("3. Resolver must read the pointer at the offset and resolve to a Node")
	fmt.Println("4. But something in that chain is failing")
}
