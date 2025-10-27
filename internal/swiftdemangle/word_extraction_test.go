package swiftdemangle

import "testing"

func TestWordExtraction(t *testing.T) {
	// Ensure literal chunk splits into expected sub-words
	chunkParser := newParser([]byte("dummy"), nil)
	chunkParser.recordWordsFromLiteral("_forceBridgeFrom")
	wantWords := []string{"force", "Bridge", "From"}
	if len(chunkParser.words) != len(wantWords) {
		t.Fatalf("unexpected word count: got %d want %d", len(chunkParser.words), len(wantWords))
	}
	for i, want := range wantWords {
		if chunkParser.words[i] != want {
			t.Fatalf("word[%d] mismatch: got %q want %q", i, chunkParser.words[i], want)
		}
	}

	// Simulate actual parsing: words from _ObjectiveCBridgeable should persist
	parser := newParser([]byte("016_forceBridgeFromA1C_6resulty"), nil)
	parser.recordWordsFromLiteral("_ObjectiveCBridgeable")
	parser.pos = 1 // skip leading '0'

	name, err := parser.readIdentifierWithWordSubstitutions()
	if err != nil {
		t.Fatalf("readIdentifierWithWordSubstitutions failed: %v", err)
	}
	if got, want := name, "_forceBridgeFromObjectiveC"; got != want {
		t.Fatalf("decoded identifier mismatch: got %q want %q", got, want)
	}
}
