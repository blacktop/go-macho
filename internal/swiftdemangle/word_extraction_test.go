package swiftdemangle

import (
	"fmt"
	"testing"
)

func TestWordExtraction(t *testing.T) {
	// Test word extraction from the CORRECT 16-char literal
	p := newParser([]byte("dummy"), nil)
	p.recordWordsFromLiteral("_forceBridgeFrom") // 16 chars, not 17!

	fmt.Printf("Words extracted from '_forceBridgeFrom' (16 chars):\n")
	for i, word := range p.words {
		fmt.Printf("  [%d] = %q\n", i, word)
	}

	// Now test the full identifier decoding
	fmt.Printf("\nTesting full identifier: 016_forceBridgeFromA1C_6resulty\n")
	p2 := newParser([]byte("016_forceBridgeFromA1C_6resulty"), nil)
	p2.pos = 1 // Skip the '0' prefix

	name, err := p2.readIdentifierWithWordSubstitutions()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		t.Fatalf("readIdentifierWithWordSubstitutions failed: %v", err)
	}

	fmt.Printf("Decoded identifier: %q\n", name)
	fmt.Printf("Final position: %d (remaining: %q)\n", p2.pos, string(p2.data[p2.pos:]))
	fmt.Printf("Word list: %v\n", p2.words)

	// Expected: "_forceBridgeFromObjectiveC"
	expected := "_forceBridgeFromObjectiveC"
	if name != expected {
		t.Errorf("Expected %q, got %q", expected, name)
	}
}
