package swiftdemangle

import (
	"fmt"

	"github.com/blacktop/go-macho/types/swift"
)

var nominalTypeKinds = map[byte]NodeKind{
	'V': KindStructure,
	'C': KindClass,
	'O': KindEnum,
	'P': KindProtocol,
	'N': KindTypeAlias,
}

// Demangler owns shared state for parsing mangled strings.
type Demangler struct {
	resolver SymbolicReferenceResolver
}

// New returns a new demangler using the provided resolver.
func New(resolver SymbolicReferenceResolver) *Demangler {
	return &Demangler{resolver: resolver}
}

// DemangleString returns both the AST and formatted representation.
func (d *Demangler) DemangleString(mangled []byte) (string, *Node, error) {
	node, err := d.DemangleType(mangled)
	if err != nil {
		return "", nil, err
	}
	return Format(node), node, nil
}

// DemangleType converts a mangled Swift type string into an AST.
func (d *Demangler) DemangleType(mangled []byte) (*Node, error) {
	if len(mangled) == 0 {
		return nil, fmt.Errorf("empty mangled string")
	}

	p := newParser(mangled, d.resolver)
	node, err := p.parseType()
	if err != nil {
		return nil, err
	}
	if !p.eof() {
		return nil, fmt.Errorf("trailing characters at position %d", p.pos)
	}
	return node, nil
}

func (p *parser) parseType() (*Node, error) {
	return p.parseTypeWithOptions(false)
}

func (p *parser) parseTypeWithOptions(allowTrailing bool) (*Node, error) {
	node, err := p.parsePrimaryType()
	if err != nil {
		return nil, err
	}

	node, err = p.parseTypeSuffix(node)
	if err != nil {
		return nil, err
	}

	for {
		fn, ok, err := p.tryParseFunctionType(node)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		node = fn
	}

	parsedTuple := false
	if !p.eof() && p.peek() == '_' {
		savePos := p.pos
		elements := []*Node{node}

		for !p.eof() && p.peek() == '_' {
			p.consume()
			if p.eof() {
				p.pos = savePos
				break
			}
			if p.peek() == 't' {
				p.consume()
				tuple := NewNode(KindTuple, "")
				tuple.Append(elements...)
				p.pushSubstitution(tuple)
				node = tuple
				parsedTuple = true
				break
			}

			elem, err := p.parseTypeWithOptions(true)
			if err != nil {
				p.pos = savePos
				break
			}
			elements = append(elements, elem)
		}

		if !parsedTuple && !p.eof() && p.peek() == 't' {
			p.consume()
			tuple := NewNode(KindTuple, "")
			tuple.Append(elements...)
			p.pushSubstitution(tuple)
			node = tuple
			parsedTuple = true
		}

		if !parsedTuple {
			p.pos = savePos
		}
	}

	node, err = p.applyOptionalSuffix(node)
	if err != nil {
		return nil, err
	}

	return node, nil
}

func (p *parser) parsePrimaryType() (*Node, error) {
	if p.eof() {
		return nil, fmt.Errorf("unexpected end while parsing type")
	}

	// Handle symbolic references first
	if b := p.peek(); b >= 0x01 && b <= 0x17 {
		control := p.consume()
		if p.resolver == nil {
			return nil, fmt.Errorf("symbolic reference encountered without resolver")
		}
		if p.pos+4 > len(p.data) {
			return nil, fmt.Errorf("symbolic reference truncated")
		}
		refIndex := p.pos
		offset := int32(p.data[p.pos]) |
			int32(p.data[p.pos+1])<<8 |
			int32(p.data[p.pos+2])<<16 |
			int32(p.data[p.pos+3])<<24
		p.pos += 4
		node, err := p.resolver.ResolveType(control, offset, refIndex)
		if err != nil {
			return nil, fmt.Errorf("resolve symbolic reference (kind %02x): %w", control, err)
		}
		p.pushSubstitution(node)
		return node, nil
	}

	// Known short substitutions (e.g. Si -> Swift.Int).
	maxLookup := 4
	if len(p.data)-p.pos < maxLookup {
		maxLookup = len(p.data) - p.pos
	}
	for l := maxLookup; l >= 1; l-- {
		if node, ok := p.lookupKnownType(l); ok {
			return node, nil
		}
	}

	// Explicit substitution references.
	if node, ok, err := p.tryParseSubstitution(); err != nil {
		return nil, err
	} else if ok {
		return node, nil
	}

	// Standard library known types (Si, SS, Sb, etc.)
	if node, ok := p.parseStandardType(); ok {
		return node, nil
	}

	// Length-prefixed identifiers (modules / nominal types).
	if c := p.peek(); c >= '0' && c <= '9' {
		return p.parseNominalOrIdentifier()
	}

	return nil, fmt.Errorf("unsupported mangled sequence starting at %d", p.pos)
}

func (p *parser) lookupKnownType(length int) (*Node, bool) {
	part := string(p.data[p.pos : p.pos+length])
	if text, ok := swift.MangledType[part]; ok {
		p.pos += length
		node := NewNode(KindIdentifier, text)
		p.pushSubstitution(node)
		return node, true
	}
	return nil, false
}

func (p *parser) parseStandardType() (*Node, bool) {
	if p.pos+1 >= len(p.data) {
		return nil, false
	}

	prefix := p.data[p.pos]
	switch prefix {
	case 'S', 's':
		name := string(p.data[p.pos+1 : p.pos+2])
		if text, ok := swift.MangledKnownTypeKind[name]; ok {
			p.pos += 2
			node := NewNode(KindIdentifier, text)
			p.pushSubstitution(node)
			return node, true
		}
		if text, ok := swift.MangledKnownTypeKind2[name]; ok {
			p.pos += 2
			node := NewNode(KindIdentifier, text)
			p.pushSubstitution(node)
			return node, true
		}
	}
	return nil, false
}

func (p *parser) parseNominalOrIdentifier() (*Node, error) {
	name, err := p.readIdentifier()
	if err != nil {
		return nil, err
	}
	firstEnd := p.pos

	names := []string{name}
	for !p.eof() {
		if c := p.peek(); c < '0' || c > '9' {
			break
		}
		next, err := p.readIdentifier()
		if err != nil {
			return nil, err
		}
		names = append(names, next)
	}

	if p.eof() {
		p.pos = firstEnd
		node := NewNode(KindIdentifier, name)
		p.pushSubstitution(node)
		return node, nil
	}

	kindChar := p.peek()
	if nodeKind, ok := nominalTypeKinds[kindChar]; ok {
		p.consume()
		node := buildNominal(nodeKind, names)
		p.pushSubstitution(node)
		return node, nil
	}

	// Not a recognized nominal type; treat as plain identifier.
	p.pos = firstEnd
	node := NewNode(KindIdentifier, name)
	p.pushSubstitution(node)
	return node, nil
}

func buildNominal(kind NodeKind, names []string) *Node {
	node := NewNode(kind, names[len(names)-1])
	switch len(names) {
	case 0:
		return node
	case 1:
		return node
	default:
		module := NewNode(KindModule, names[0])
		node.Append(module)
		for _, parent := range names[1 : len(names)-1] {
			node.Append(NewNode(KindIdentifier, parent))
		}
		return node
	}
}

func (p *parser) tryParseSubstitution() (*Node, bool, error) {
	if p.peek() != 'S' {
		return nil, false, nil
	}

	start := p.pos
	p.consume() // 'S'

	if p.eof() {
		p.pos = start
		return nil, false, fmt.Errorf("unterminated substitution at end of input")
	}

	index := 0
	digitCount := 0
	for !p.eof() {
		ch := p.peek()
		if ch == '_' {
			break
		}
		val, ok := fromBase36(ch)
		if !ok {
			// Not a substitution; rewind and let other logic handle (e.g. So… bridging types).
			p.pos = start
			return nil, false, nil
		}
		index = index*36 + val
		digitCount++
		p.consume()
	}

	if p.eof() || p.peek() != '_' {
		// No terminating underscore; rewind and treat as non-substitution.
		p.pos = start
		return nil, false, nil
	}
	p.consume() // consume '_'

	if digitCount == 0 {
		index = 0
	} else {
		index++
	}

	node, err := p.lookupSubstitution(index)
	if err != nil {
		return nil, false, err
	}
	return node.Clone(), true, nil
}

func (p *parser) parseTypeSuffix(base *Node) (*Node, error) {
	current := base
	for !p.eof() {
		switch p.peek() {
		case 'y':
			p.consume()
			bound, err := p.parseBoundGeneric(current)
			if err != nil {
				return nil, err
			}
			current = bound
		default:
			return current, nil
		}
	}
	return current, nil
}

func (p *parser) parseBoundGeneric(base *Node) (*Node, error) {
	if base == nil {
		return nil, fmt.Errorf("bound generic base is nil")
	}

	args := []*Node{}
	for {
		if p.eof() {
			return nil, fmt.Errorf("unterminated bound generic")
		}
		if p.peek() == 'G' {
			p.consume()
			break
		}

		arg, err := p.parseType()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)

		if p.eof() {
			return nil, fmt.Errorf("unterminated bound generic")
		}
		if p.peek() == '_' {
			p.consume()
			continue
		}
	}

	genericArgs := NewNode(KindGenericArgs, "")
	genericArgs.Append(args...)
	bound := NewNode(KindBoundGeneric, "")
	bound.Append(base, genericArgs)

	sugared := applyOptionalSugar(bound)
	p.pushSubstitution(sugared)
	return sugared, nil
}

func applyOptionalSugar(node *Node) *Node {
	if node == nil || node.Kind != KindBoundGeneric || len(node.Children) < 2 {
		return node
	}

	base := node.Children[0]
	argsNode := node.Children[1]
	if base == nil || argsNode == nil || len(argsNode.Children) != 1 {
		return node
	}

	arg := argsNode.Children[0]

	switch {
	case isSwiftNominal(base, "Swift.Optional"):
		opt := NewNode(KindOptional, "")
		opt.Append(arg)
		return opt
	case isSwiftNominal(base, "Swift.ImplicitlyUnwrappedOptional"):
		opt := NewNode(KindImplicitlyUnwrappedOptional, "")
		opt.Append(arg)
		return opt
	default:
		return node
	}
}

func isSwiftNominal(node *Node, fullyQualifiedName string) bool {
	if node == nil {
		return false
	}
	if node.Kind == KindIdentifier && node.Text == fullyQualifiedName {
		return true
	}

	if (node.Kind == KindStructure || node.Kind == KindClass || node.Kind == KindEnum || node.Kind == KindTypeAlias || node.Kind == KindProtocol) && node.Text != "" {
		if len(node.Children) > 0 {
			if node.Children[0].Kind == KindModule && node.Children[0].Text == "Swift" {
				return fmt.Sprintf("Swift.%s", node.Text) == fullyQualifiedName
			}
		}
	}

	return false
}

func (p *parser) tryParseFunctionType(result *Node) (*Node, bool, error) {
	start := p.pos

	if p.eof() {
		return nil, false, nil
	}

	params, ok, err := p.parseFunctionInput()
	if err != nil {
		return nil, false, err
	}
	if !ok {
		p.pos = start
		return nil, false, nil
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

	if p.eof() || p.peek() != 'c' {
		p.pos = start
		return nil, false, nil
	}
	p.consume()

	fn := NewNode(KindFunction, "")
	fn.Flags.Async = async
	fn.Flags.Throws = throws
	fn.Append(params, result)
	p.pushSubstitution(fn)
	return fn, true, nil
}

func (p *parser) parseFunctionInput() (*Node, bool, error) {
	start := p.pos

	if p.eof() {
		return nil, false, nil
	}

	// Empty tuple is encoded as 'y' 'y' ... handle simple 'yy' -> ()
	if p.peek() == 'y' {
		p.consume()
		if !p.eof() && p.peek() == 'y' {
			p.consume()
			tuple := NewNode(KindTuple, "")
			p.pushSubstitution(tuple)
			return tuple, true, nil
		}
		p.pos = start
		return nil, false, nil
	}

	params := []*Node{}
	for {
		param, err := p.parseType()
		if err != nil {
			p.pos = start
			return nil, false, nil
		}
		params = append(params, param)

		if p.eof() {
			break
		}

		if p.peek() == '_' {
			p.consume()
			if !p.eof() && p.peek() == 't' {
				p.consume()
				break
			}
			continue
		}

		if p.peek() == 't' {
			p.consume()
		} else {
			// No more parameters; ensure we haven't inadvertently consumed async/throws markers.
			// Leave position as-is for outer parser.
		}
		break
	}

	if len(params) == 0 {
		p.pos = start
		return nil, false, nil
	}

	if len(params) == 1 && params[0].Kind == KindTuple {
		return params[0], true, nil
	}

	tuple := NewNode(KindTuple, "")
	tuple.Append(params...)
	p.pushSubstitution(tuple)
	return tuple, true, nil
}

func (p *parser) applyOptionalSuffix(node *Node) (*Node, error) {
	for !p.eof() {
		if p.matchString("Sg") {
			p.pos += 2
			wrapped := NewNode(KindOptional, "")
			wrapped.Append(node)
			node = wrapped
			continue
		}
		if p.matchString("SgXw") {
			p.pos += 4
			wrapped := NewNode(KindImplicitlyUnwrappedOptional, "")
			wrapped.Append(node)
			node = wrapped
			continue
		}
		break
	}
	return node, nil
}

func (p *parser) matchString(s string) bool {
	if len(p.data)-p.pos < len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if p.data[p.pos+i] != s[i] {
			return false
		}
	}
	return true
}
