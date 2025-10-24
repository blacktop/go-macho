package swiftdemangle

import (
	"fmt"
)

// SymbolicReferenceResolver resolves symbolic reference offsets found in mangled
// strings. Implementations must interpret the offset relative to the address of
// the reference site and return a preconstructed node representing the target
// context or type.
type SymbolicReferenceResolver interface {
	ResolveType(control byte, offset int32, refIndex int) (*Node, error)
}

type parser struct {
	data     []byte
	pos      int
	resolver SymbolicReferenceResolver
	subst    []*Node
}

func newParser(data []byte, resolver SymbolicReferenceResolver) *parser {
	return &parser{
		data:     data,
		resolver: resolver,
	}
}

func (p *parser) eof() bool {
	return p.pos >= len(p.data)
}

func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.data[p.pos]
}

func (p *parser) consume() byte {
	if p.eof() {
		return 0
	}
	b := p.data[p.pos]
	p.pos++
	return b
}

func (p *parser) expect(b byte) error {
	if p.eof() {
		return fmt.Errorf("unexpected end of mangled name, expected %q", b)
	}
	if p.data[p.pos] != b {
		return fmt.Errorf("unexpected character %q at position %d, expected %q", p.data[p.pos], p.pos, b)
	}
	p.pos++
	return nil
}

func (p *parser) readNumber() (int, error) {
	if p.eof() {
		return 0, fmt.Errorf("unexpected end while reading number")
	}
	start := p.pos
	total := 0
	for !p.eof() {
		c := p.data[p.pos]
		if c < '0' || c > '9' {
			break
		}
		total = total*10 + int(c-'0')
		p.pos++
	}
	if p.pos == start {
		return 0, fmt.Errorf("expected digit at position %d", start)
	}
	return total, nil
}

func (p *parser) readIdentifier() (string, error) {
	length, err := p.readNumber()
	if err != nil {
		return "", err
	}
	if length <= 0 {
		return "", fmt.Errorf("identifier length must be >0, got %d", length)
	}
	if p.pos+length > len(p.data) {
		return "", fmt.Errorf("identifier exceeds input length")
	}
	start := p.pos
	p.pos += length
	return string(p.data[start:p.pos]), nil
}

func (p *parser) pushSubstitution(n *Node) {
	if n == nil {
		return
	}
	p.subst = append(p.subst, n)
}

func (p *parser) lookupSubstitution(index int) (*Node, error) {
	if index < 0 || index >= len(p.subst) {
		return nil, fmt.Errorf("invalid substitution index %d", index)
	}
	return p.subst[index], nil
}

func fromBase36(b byte) (int, bool) {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0'), true
	case b >= 'A' && b <= 'Z':
		return int(b-'A') + 10, true
	default:
		return 0, false
	}
}
