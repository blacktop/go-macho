package swiftdemangle

import (
	"bytes"
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
	clean := bytes.TrimPrefix(mangled, []byte("_"))
	if len(clean) > 1 && clean[0] == '$' {
		if node, err := d.DemangleSymbol(mangled); err == nil {
			return Format(node), node, nil
		}
	}
	node, err := d.DemangleType(mangled)
	if err != nil {
		return "", nil, err
	}
	return Format(node), node, nil
}

// DemangleSymbol converts a mangled Swift symbol string into an AST.
func (d *Demangler) DemangleSymbol(mangled []byte) (*Node, error) {
	if len(mangled) == 0 {
		return nil, fmt.Errorf("empty symbol string")
	}
	clean := bytes.TrimPrefix(mangled, []byte("_"))
	if len(clean) < 2 || clean[0] != '$' {
		return nil, fmt.Errorf("not a mangled symbol")
	}

	p := newParser(clean, d.resolver)
	node, err := p.parseSymbol()
	if err != nil {
		return nil, err
	}
	if !p.eof() {
		return nil, fmt.Errorf("trailing characters at position %d", p.pos)
	}
	return node, nil
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
	node, err := p.parseTypeWithOptions(false)
	if err != nil {
		return nil, err
	}
	if node != nil {
		p.pushSubstitution(node)
	}
	return node, nil
}

func (p *parser) parseTypeWithOptions(allowTrailing bool) (*Node, error) {
	node, err := p.parsePrimaryType()
	if err != nil {
		return nil, err
	}

	node, err = p.parseContextualSuffix(node)
	if err != nil {
		return nil, err
	}

	node, err = p.parseTypeSuffix(node)
	if err != nil {
		return nil, err
	}

	if tuple, ok, err := p.tryParseTuple(node); err != nil {
		return nil, err
	} else if ok {
		node = tuple
		if !allowTrailing {
			if fn, fnOK, err := p.tryParseFunctionAfterTuple(node); err != nil {
				return nil, err
			} else if fnOK {
				node = fn
			}
		}
	}

	if !allowTrailing {
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
	}

	node, err = p.applyOptionalSuffix(node)
	if err != nil {
		return nil, err
	}

	return node, nil
}

func (p *parser) parsePrimaryType() (*Node, error) {
	if len(p.pending) > p.pendingFloor {
		idx := len(p.pending) - 1
		node := p.pending[idx]
		p.pending = p.pending[:idx]
		if debugEnabled {
			debugf("parsePrimaryType returning pending node %s (pos=%d)\n", Format(node), p.pos)
		}
		return node, nil
	}
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
			if debugEnabled {
				debugf("parsePrimaryType: lookupKnownType hit %q -> %s\n", string(p.data[p.pos-l:p.pos]), Format(node))
			}
			return node, nil
		}
	}

	if ok, err := p.tryParseMultiSubstitution(); err != nil {
		return nil, err
	} else if ok {
		return p.parsePrimaryType()
	}

	// Standard library known types (Si, SS, Sb, etc.)
	if node, ok := p.parseStandardType(); ok {
		if debugEnabled {
			debugf("parsePrimaryType: standard type %s at pos=%d\n", Format(node), p.pos)
		}
		return node, nil
	}

	// Special stdlib nominal short-hands (e.g. s4Int8V -> Swift.Int8).
	if !p.eof() && p.peek() == 's' {
		if node, ok, err := p.tryParseStdlibNominal(); err != nil {
			return nil, err
		} else if ok {
			return node, nil
		}
	}

	// Length-prefixed identifiers (modules / nominal types).
	if c := p.peek(); c >= '0' && c <= '9' {
		return p.parseNominalOrIdentifier()
	}

	// Explicit substitution references.
	if node, ok, err := p.tryParseSubstitution(); err != nil {
		return nil, err
	} else if ok {
		return node, nil
	}

	if debugEnabled {
		debugf("parsePrimaryType unsupported at pos=%d char=%q remaining=%s\n", p.pos, func() byte {
			if p.pos < len(p.data) {
				return p.data[p.pos]
			}
			return 0
		}(), string(p.data[p.pos:]))
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
	if len(p.data)-p.pos >= 3 && (prefix == 'S' || prefix == 's') && p.data[p.pos+1] == 'c' {
		key := string(p.data[p.pos+2 : p.pos+3])
		if text, ok := swift.MangledKnownTypeKind2[key]; ok {
			p.pos += 3
			node := NewNode(KindIdentifier, text)
			p.pushSubstitution(node)
			return node, true
		}
	}

	if prefix == 'S' && p.data[p.pos+1] == 'o' {
		start := p.pos
		p.pos += 2
		name, err := p.readIdentifier()
		if err != nil {
			p.pos = start
			return nil, false
		}
		if p.eof() {
			p.pos = start
			return nil, false
		}
		kind := p.peek()
		if kind != 'C' {
			p.pos = start
			return nil, false
		}
		p.consume()
		node := NewNode(KindClass, name)
		node.Append(NewNode(KindModule, "__C"))
		p.pushSubstitution(node)
		return node, true
	}

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
		return NewNode(KindIdentifier, name), nil
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
	return NewNode(KindIdentifier, name), nil
}

func (p *parser) tryParseStdlibNominal() (*Node, bool, error) {
	if p.peek() != 's' {
		return nil, false, nil
	}
	savePos := p.pos
	p.consume() // consume 's'

	names := []string{"Swift"}
	name, err := p.readIdentifier()
	if err != nil {
		p.pos = savePos
		return nil, false, nil
	}
	names = append(names, name)

	for !p.eof() {
		if c := p.peek(); c < '0' || c > '9' {
			break
		}
		next, err := p.readIdentifier()
		if err != nil {
			p.pos = savePos
			return nil, false, nil
		}
		names = append(names, next)
	}

	if p.eof() {
		p.pos = savePos
		return nil, false, nil
	}
	kindChar := p.peek()
	nodeKind, ok := nominalTypeKinds[kindChar]
	if !ok {
		p.pos = savePos
		return nil, false, nil
	}
	p.consume()
	node := buildNominal(nodeKind, names)
	p.pushSubstitution(node)
	return node, true, nil
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

func collectContextNames(node *Node) []string {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case KindModule:
		return []string{node.Text}
	case KindIdentifier:
		return []string{node.Text}
	case KindStructure, KindClass, KindEnum, KindProtocol, KindTypeAlias:
		names := []string{}
		if len(node.Children) > 0 && node.Children[0].Kind == KindModule {
			names = append(names, node.Children[0].Text)
		}
		for i := 1; i < len(node.Children); i++ {
			names = append(names, node.Children[i].Text)
		}
		names = append(names, node.Text)
		return names
	default:
		if node.Text != "" {
			return []string{node.Text}
		}
		return nil
	}
}

func (p *parser) parseContextualSuffix(base *Node) (*Node, error) {
	current := base
	for {
		if p.eof() {
			return current, nil
		}
		save := p.pos
		if !isDigit(p.peek()) {
			return current, nil
		}
		name, err := p.readIdentifierNoSubst()
		if err != nil {
			p.pos = save
			return current, nil
		}
		if p.eof() {
			p.pos = save
			return current, nil
		}
		kindChar := p.peek()
		nodeKind, ok := nominalTypeKinds[kindChar]
		if !ok {
			p.pos = save
			return current, nil
		}
		p.consume()
		names := append(collectContextNames(current), name)
		if len(names) == 0 {
			p.pos = save
			return current, nil
		}
		next := buildNominal(nodeKind, names)
		current = next
		p.pushSubstitution(current)
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

func (p *parser) tryParseMultiSubstitution() (bool, error) {
	if p.peek() != 'A' {
		return false, nil
	}
	start := p.pos
	p.consume()

	repeat := -1
	for {
		if p.eof() {
			p.pos = start
			return false, fmt.Errorf("unterminated multi substitution")
		}
		c := p.peek()
		switch {
		case c >= 'a' && c <= 'z':
			p.consume()
			idx := int(c - 'a')
			node, err := p.lookupSubstitution(idx)
			if err != nil {
				return false, err
			}
			count := 1
			if repeat > 0 {
				count = repeat
			}
			p.pushPendingNode(node, count)
			repeat = -1
			continue
		case c >= 'A' && c <= 'Z':
			p.consume()
			idx := int(c - 'A')
			node, err := p.lookupSubstitution(idx)
			if err != nil {
				return false, err
			}
			count := 1
			if repeat > 0 {
				count = repeat
			}
			p.pushPendingNode(node, count)
			repeat = -1
			return true, nil
		case c == '_':
			p.consume()
			if repeat < 0 {
				return false, fmt.Errorf("large multi substitution index without count")
			}
			idx := repeat + 27
			node, err := p.lookupSubstitution(idx)
			if err != nil {
				return false, err
			}
			p.pushPendingNode(node, 1)
			repeat = -1
			return true, nil
		case c >= '0' && c <= '9':
			num, err := p.readNumber()
			if err != nil {
				return false, err
			}
			repeat = num
			continue
		default:
			p.pos = start
			return false, nil
		}
	}
}

func (p *parser) parseTypeSuffix(base *Node) (*Node, error) {
	current := base
	for !p.eof() {
		switch p.peek() {
		case 'y':
			save := p.pos
			p.consume()
			bound, err := p.parseBoundGeneric(current)
			if err != nil {
				// Not actually a bound generic suffix; rewind and stop parsing suffixes so other
				// grammar components (e.g. empty tuple markers) can consume the 'y'.
				p.pos = save
				return current, nil
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

	sugared := applyTypeSugar(bound)
	p.pushSubstitution(sugared)
	return sugared, nil
}

func applyTypeSugar(node *Node) *Node {
	if node == nil || node.Kind != KindBoundGeneric || len(node.Children) < 2 {
		return node
	}

	base := node.Children[0]
	argsNode := node.Children[1]
	if base == nil || argsNode == nil || len(argsNode.Children) == 0 {
		return node
	}

	args := argsNode.Children

	switch {
	case isSwiftNominal(base, "Swift.Optional") && len(args) == 1:
		opt := NewNode(KindOptional, "")
		opt.Append(args[0])
		return opt
	case isSwiftNominal(base, "Swift.ImplicitlyUnwrappedOptional") && len(args) == 1:
		opt := NewNode(KindImplicitlyUnwrappedOptional, "")
		opt.Append(args[0])
		return opt
	case isSwiftNominal(base, "Swift.Array") && len(args) == 1:
		arr := NewNode(KindArray, "")
		arr.Append(args[0])
		return arr
	case isSwiftNominal(base, "Swift.Dictionary") && len(args) == 2:
		dict := NewNode(KindDictionary, "")
		dict.Append(args[0], args[1])
		return dict
	case isSwiftNominal(base, "Swift.Set") && len(args) == 1:
		setNode := NewNode(KindSet, "")
		setNode.Append(args[0])
		return setNode
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

	switch p.peek() {
	case 'v', 'f', 'F', 'c', 't', 'W', 'M', 'T':
		return nil, false, nil
	}

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
	return fn, true, nil
}

func (p *parser) parseFunctionInput() (*Node, bool, error) {
	start := p.pos

	if p.eof() {
		return nil, false, nil
	}
	p.pushPendingScope()
	defer p.popPendingScope()

	if debugEnabled {
		next := byte(0)
		if !p.eof() {
			next = p.data[p.pos]
		}
		next2 := byte(0)
		if p.pos+1 < len(p.data) {
			next2 = p.data[p.pos+1]
		}
		debugf("parseFunctionInput: start=%d remaining=%q pendingLen=%d floor=%d next=%q next2=%q\n", start, string(p.data[start:]), len(p.pending), p.pendingFloor, next, next2)
	}
	// fmt.Printf("parseFunctionInput start pos=%d char=%c\n", p.pos, p.peek())
	// fmt.Printf("parseFunctionInput start pos=%d char=%c\n", p.pos, p.peek())

	// Empty tuple is encoded as 'y' (optionally repeated). Accept single 'y'.
	if p.peek() == 'y' {
		p.consume()
		if !p.eof() && p.peek() == 'y' {
			p.consume()
		}
		tuple := NewNode(KindTuple, "")
		return tuple, true, nil
	}

	node, err := p.parseTypeWithOptions(true)
	if err != nil {
		p.pos = start
		return nil, false, nil
	}
	if node != nil {
		p.pushSubstitution(node)
	}
	if debugEnabled {
		debugf("parseFunctionInput: parsed node=%s kind=%v pos=%d remaining=%q\n", func() string {
			if node != nil {
				return Format(node)
			}
			return "<nil>"
		}(), func() interface{} {
			if node != nil {
				return node.Kind
			}
			return "<nil>"
		}(), p.pos, string(p.data[p.pos:]))
	}

	if node.Kind == KindTuple {
		return node, true, nil
	}

	tuple := NewNode(KindTuple, "")
	tuple.Append(node)
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

func (p *parser) tryParseTuple(node *Node) (*Node, bool, error) {
	if p.eof() || p.peek() != '_' {
		return node, false, nil
	}

	savePos := p.pos
	elements := []*Node{node}

	for !p.eof() && p.peek() == '_' {
		p.consume()
		if p.eof() {
			p.pos = savePos
			return node, false, nil
		}
		if p.peek() == 't' {
			p.consume()
			tuple := NewNode(KindTuple, "")
			tuple.Append(elements...)
			return tuple, true, nil
		}

		elem, err := p.parseTypeWithOptions(true)
		if err != nil {
			p.pos = savePos
			return node, false, nil
		}
		elements = append(elements, elem)
	}

	if !p.eof() && p.peek() == 't' {
		p.consume()
		tuple := NewNode(KindTuple, "")
		tuple.Append(elements...)
		return tuple, true, nil
	}

	p.pos = savePos
	return node, false, nil
}

func (p *parser) tryParseFunctionAfterTuple(tuple *Node) (*Node, bool, error) {
	if tuple == nil {
		return nil, false, nil
	}

	savePos := p.pos
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
		p.pos = savePos
		return tuple, false, nil
	}

	p.consume()
	result, err := p.parseType()
	if err != nil {
		return nil, false, err
	}

	fn := NewNode(KindFunction, "")
	fn.Flags.Async = async
	fn.Flags.Throws = throws
	fn.Append(tuple, result)
	return fn, true, nil
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
