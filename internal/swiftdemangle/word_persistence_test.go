package swiftdemangle

import (
	"fmt"
	"testing"
)

func TestWordPersistence(t *testing.T) {
	// Simulate parsing the protocol name, then the entity name
	p := newParser([]byte("dummy"), nil)

	// First, "read" the protocol name (21 chars)
	protocolName := "_ObjectiveCBridgeable"
	fmt.Printf("Protocol name (%d chars): %q\n", len(protocolName), protocolName)
	p.recordWordsFromLiteral(protocolName)

	fmt.Printf("Words after protocol name:\n")
	for i, word := range p.words {
		fmt.Printf("  [%d] = %q\n", i, word)
	}

	// Now "read" the first chunk of entity name
	entityChunk := "_forceBridgeFrom"
	fmt.Printf("\nEntity name chunk (%d chars): %q\n", len(entityChunk), entityChunk)
	p.recordWordsFromLiteral(entityChunk)

	fmt.Printf("Words after entity chunk:\n")
	for i, word := range p.words {
		fmt.Printf("  [%d] = %q\n", i, word)
	}

	// Now check: word[0] should give us "ObjectiveC" if this is correct
	fmt.Printf("\nWord[0] = %q (expected: \"ObjectiveC\" or \"Objective\")\n", p.words[0])
}
