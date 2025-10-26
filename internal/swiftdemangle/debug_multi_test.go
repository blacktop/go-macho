//go:build debugmulti

package swiftdemangle

import "testing"

func TestDebugConstructorParse(t *testing.T) {
	data := []byte("16DemangleFixtures15ObjCBridgeClassC5label7payloadACSS_AA5OuterV5InnerVtcfC")
	p := newParser(data, nil)
	module, err := p.readIdentifier()
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	_ = module
	for {
		save := p.pos
		if p.eof() || !isDigit(p.peek()) {
			p.pos = save
			break
		}
		name, err := p.readIdentifier()
		if err != nil {
			p.pos = save
			break
		}
		if p.eof() {
			p.pos = save
			break
		}
		kind := p.peek()
		if !isContextKind(kind) {
			p.pos = save
			break
		}
		p.consume()
		_ = name
	}
	labels, err := p.parseLabelList()
	if err != nil {
		t.Fatalf("labels err=%v", err)
	}
	params, async, throws, err := p.parseFunctionSignature()
	if err != nil {
		t.Fatalf("signature err=%v", err)
	}
	t.Logf("labels=%v params=%d async=%v throws=%v", labels, len(params), async, throws)
}
