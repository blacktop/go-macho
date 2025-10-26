package swiftdemangle

import (
	"fmt"
	"testing"
)

func TestDemangleSymbolDebug(t *testing.T) {
	sym := "_$ss21_ObjectiveCBridgeableP016_forceBridgeFromA1C_6resulty01_A5CTypeQz_xSgztFZTq"
	d := New(nil)

	// Try as symbol first
	node, err := d.DemangleSymbol([]byte(sym))
	if err != nil {
		fmt.Printf("DemangleSymbol error at pos: %v\n", err)
		t.Logf("DemangleSymbol error: %v", err)
	} else {
		fmt.Printf("DemangleSymbol success: %s\n", Format(node))
		t.Logf("DemangleSymbol success: %s", Format(node))
	}

	// Test entity name parsing WITH the protocol's word list
	fmt.Printf("\nTesting entity name parsing:\n")
	entityTest := "016_forceBridgeFromA1C_6resulty"
	pEntity := newParser([]byte(entityTest), nil)
	// Simulate having parsed the protocol name first
	pEntity.recordWordsFromLiteral("_ObjectiveCBridgeable")
	pEntity.pos = 1 // Skip the '0' prefix
	name, err := pEntity.readIdentifierWithWordSubstitutions()
	if err != nil {
		fmt.Printf("readEntityName error: %v\n", err)
		t.Logf("readEntityName error: %v", err)
	} else {
		fmt.Printf("readEntityName success: %q (pos=%d remaining=%q)\n", name, pEntity.pos, string(pEntity.data[pEntity.pos:]))
		t.Logf("readEntityName success: %q", name)
	}

	// Also test the substring starting from the parameter tuple
	// Position 52 is where 'y01_A5CTypeQz_xSgzt' starts
	paramTest := "y01_A5CTypeQz_xSgzt"
	fmt.Printf("\nTesting parameter tuple directly: %s\n", paramTest)
	p2 := newParser([]byte(paramTest), nil)
	tuple, err := p2.parseParameterTuple()
	if err != nil {
		fmt.Printf("parseParameterTuple error: %v\n", err)
		t.Logf("parseParameterTuple error: %v", err)
	} else {
		fmt.Printf("parseParameterTuple success: %s\n", Format(tuple))
		t.Logf("parseParameterTuple success: %s", Format(tuple))
	}
}
