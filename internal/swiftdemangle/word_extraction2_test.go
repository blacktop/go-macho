package swiftdemangle

import (
	"fmt"
	"testing"
)

func TestWordExtraction2(t *testing.T) {
	// Test word extraction from the CORRECT 16-char string
	literal := "_forceBridgeFrom"  // 16 characters
	fmt.Printf("Literal (%d chars): %q\n", len(literal), literal)
	
	p := newParser([]byte("dummy"), nil)
	p.recordWordsFromLiteral(literal)
	
	fmt.Printf("Words extracted:\n")
	for i, word := range p.words {
		fmt.Printf("  [%d] = %q\n", i, word)
	}
}
