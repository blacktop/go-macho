package swiftdemangle

import "testing"

func TestDemangleSymbolString(t *testing.T) {
	symbol := "_$s16DemangleFixtures7CounterC5valueSivg"
	text, node, err := DemangleSymbolString(symbol)
	if err != nil {
		t.Fatalf("DemangleSymbolString failed: %v", err)
	}
	if node == nil {
		t.Fatalf("expected node, got nil")
	}
	want := "DemangleFixtures.Counter.value.getter : Swift.Int"
	if text != want {
		t.Fatalf("unexpected demangle text: got %q want %q", text, want)
	}
}

func TestDemangleTypeString(t *testing.T) {
	text, node, err := DemangleTypeString("Si_SSt")
	if err != nil {
		t.Fatalf("DemangleTypeString failed: %v", err)
	}
	if node == nil || node.Kind != KindTuple {
		t.Fatalf("unexpected node for tuple: %#v", node)
	}
	if text != "(Swift.Int, Swift.String)" {
		t.Fatalf("unexpected tuple text: %q", text)
	}
}

func TestDemangleBlob(t *testing.T) {
	blob := "call _$s16DemangleFixtures7CounterC5valueSivg"
	out := DemangleBlob(blob)
	if out == blob {
		t.Fatalf("expected blob to change")
	}
	if want := "call DemangleFixtures.Counter.value.getter : Swift.Int"; out != want {
		t.Fatalf("unexpected blob output: %q", out)
	}
}
