package swiftdemangle

import (
	"fmt"
	"strings"
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

func isContextKind(b byte) bool {
	switch b {
	case 'C', 'V', 'O', 'E', 'P', 'N', 'B', 'I', 'A', 'G', 'M', 'T':
		return true
	default:
		return false
	}
}

func (p *parser) parseSymbol() (*Node, error) {
	if p.eof() {
		return nil, fmt.Errorf("empty symbol")
	}

	if p.peek() == '_' {
		p.consume()
	}

	if err := p.expect('$'); err != nil {
		return nil, err
	}
	if p.eof() {
		return nil, fmt.Errorf("unexpected end after $")
	}

	prefix := p.peek()
	if prefix != 's' && prefix != 'S' {
		return nil, fmt.Errorf("unsupported symbol prefix %q", prefix)
	}
	p.consume()

	moduleName, err := p.readIdentifier()
	if err != nil {
		return nil, fmt.Errorf("failed to read module: %w", err)
	}
	moduleNode := NewNode(KindModule, moduleName)
	p.pushSubstitution(moduleNode)

	var contextNames []string
	var contextNodes []*Node
	for {
		savePos := p.pos
		name, err := p.readIdentifier()
		if err != nil {
			p.pos = savePos
			break
		}
		if p.eof() {
			p.pos = savePos
			break
		}
		kind := p.peek()
		if !isContextKind(kind) {
			p.pos = savePos
			break
		}
		p.consume()

		pathNames := append([]string{moduleName}, append(contextNames, name)...)
		node := buildNominal(nominalTypeKinds[kind], pathNames)
		contextNames = append(contextNames, name)
		contextNodes = append(contextNodes, node)
		p.pushSubstitution(node)
	}

	entity, err := p.parseSymbolEntity(moduleName, contextNames)
	if err != nil {
		return nil, err
	}
	return entity, nil
}

func (p *parser) parseSymbolEntity(moduleName string, contextNames []string) (*Node, error) {
	name, err := p.readIdentifier()
	if err != nil {
		return nil, fmt.Errorf("failed to read entity name: %w", err)
	}

	labels := []string{}
	for !p.eof() && p.peek() == '_' {
		p.consume()
		if p.eof() {
			break
		}
		if p.peek() >= '0' && p.peek() <= '9' {
			label, err := p.readIdentifier()
			if err != nil {
				return nil, err
			}
			labels = append(labels, label)
		} else {
			labels = append(labels, "_")
		}
	}

	node, err := p.parseFunctionEntity(moduleName, contextNames, name, labels)
	if err != nil {
		return nil, err
	}
	return node, nil
}

func (p *parser) parseFunctionEntity(moduleName string, contextNames []string, baseName string, labels []string) (*Node, error) {
	resultType, err := p.parseType()
	if err != nil {
		return nil, fmt.Errorf("failed to parse function result type: %w", err)
	}

	savePos := p.pos
	paramsTuple := NewNode(KindTuple, "")
	if tuple, ok, err := p.parseFunctionInput(); err != nil {
		return nil, err
	} else if ok {
		paramsTuple = tuple
	} else {
		p.pos = savePos
	}

	async := false
	throws := false

	if !p.eof() && p.peek() == 'Y' {
		async = true
		p.consume()
		if !p.eof() && p.peek() == 'a' {
			p.consume()
		}
	}
	if !p.eof() && p.peek() == 'K' {
		throws = true
		p.consume()
	}

	if err := p.expect('F'); err != nil {
		return nil, fmt.Errorf("expected function suffix: %w", err)
	}

	paramNodes := []*Node{}
	switch paramsTuple.Kind {
	case KindTuple:
		paramNodes = append(paramNodes, paramsTuple.Children...)
	case KindArgumentTuple:
		paramNodes = append(paramNodes, paramsTuple.Children...)
	case KindUnknown:
		if paramsTuple != nil {
			paramNodes = append(paramNodes, paramsTuple)
		}
	default:
		if paramsTuple != nil {
			paramNodes = append(paramNodes, paramsTuple)
		}
	}

	normalized := normalizeArgumentLabels(len(paramNodes), labels)
	argumentTuple := NewNode(KindArgumentTuple, "")
	for idx, param := range paramNodes {
		arg := NewNode(KindArgument, normalized[idx])
		arg.Append(param)
		argumentTuple.Append(arg)
	}

	funcNode := NewNode(KindFunction, buildQualifiedName(moduleName, contextNames, baseName))
	funcNode.Flags.Async = async
	funcNode.Flags.Throws = throws
	funcNode.Append(argumentTuple, resultType)
	return funcNode, nil
}

func normalizeArgumentLabels(paramCount int, labels []string) []string {
	if paramCount == 0 {
		return nil
	}
	normalized := make([]string, paramCount)
	for i := range normalized {
		normalized[i] = "_"
	}
	if len(labels) == paramCount-1 {
		copy(normalized[1:], labels)
		return normalized
	}
	start := paramCount - len(labels)
	if start < 0 {
		start = 0
	}
	for i := 0; i < len(labels) && start+i < paramCount; i++ {
		if labels[i] != "" {
			normalized[start+i] = labels[i]
		}
	}
	return normalized
}

func buildQualifiedName(module string, contexts []string, base string) string {
	parts := []string{module}
	parts = append(parts, contexts...)
	if base != "" {
		parts = append(parts, base)
	}
	return strings.Join(parts, ".")
}
