package swiftdemangle

import (
	"bytes"
	"fmt"
	"strings"
	"unsafe"

	"github.com/blacktop/go-macho/types/swift"
)

const pointerWidth = int(unsafe.Sizeof(uintptr(0)))

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
		} else if debugEnabled {
			debugf("DemangleString: DemangleSymbol failed: %v, falling back to DemangleType\n", err)
		}
	}
	node, err := d.DemangleType(clean)
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

	clean := bytes.TrimPrefix(mangled, []byte("_"))
	p := newParser(clean, d.resolver)
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
	baseStack := len(p.typeStack)
	defer func() {
		if len(p.typeStack) > baseStack {
			p.typeStack = p.typeStack[:baseStack]
		}
	}()
	if debugEnabled {
		debugf("parseType: entry at pos=%d remaining=%q\n", p.pos, string(p.data[p.pos:]))
	}
	node, err := p.parseTypeWithOptions(false)
	if err != nil {
		if debugEnabled {
			debugf("parseType: parseTypeWithOptions failed: %v\n", err)
		}
		return nil, err
	}
	if node != nil {
		p.pushSubstitution(node)
	}
	if debugEnabled {
		debugf("parseType: success, parsed %s, pos now %d\n", Format(node), p.pos)
	}
	return node, nil
}

func (p *parser) parseTypeAllowTrailing() (*Node, error) {
	baseStack := len(p.typeStack)
	defer func() {
		if len(p.typeStack) > baseStack {
			p.typeStack = p.typeStack[:baseStack]
		}
	}()
	if debugEnabled {
		debugf("parseTypeAllowTrailing: entry at pos=%d remaining=%q\n", p.pos, string(p.data[p.pos:]))
	}
	node, err := p.parseTypeWithOptions(true)
	if err != nil {
		if debugEnabled {
			debugf("parseTypeAllowTrailing: parseTypeWithOptions failed: %v\n", err)
		}
		return nil, err
	}
	if node != nil {
		p.pushSubstitution(node)
	}
	if debugEnabled {
		debugf("parseTypeAllowTrailing: success, parsed %s, pos now %d\n", Format(node), p.pos)
	}
	return node, nil
}

func (p *parser) parseTypeWithOptions(allowTrailing bool) (*Node, error) {
	if debugEnabled {
		debugf("parseTypeWithOptions: entry at pos=%d allowTrailing=%v\n", p.pos, allowTrailing)
	}
	node, err := p.parsePrimaryType()
	if err != nil {
		return nil, err
	}
	if debugEnabled {
		debugf("parseTypeWithOptions: after parsePrimaryType, node=%s pos=%d\n", Format(node), p.pos)
	}

	node, err = p.parseContextualSuffix(node)
	if err != nil {
		return nil, err
	}
	if debugEnabled {
		debugf("parseTypeWithOptions: after parseContextualSuffix, pos=%d\n", p.pos)
	}

	node, err = p.parseTypeSuffix(node)
	if err != nil {
		return nil, err
	}
	if debugEnabled {
		debugf("parseTypeWithOptions: after parseTypeSuffix, pos=%d\n", p.pos)
	}

	if tuple, ok, err := p.tryParseTuple(node); err != nil {
		return nil, err
	} else if ok {
		node = tuple
		if debugEnabled {
			debugf("parseTypeWithOptions: parsed tuple, pos=%d\n", p.pos)
		}
		if !allowTrailing {
			if fn, fnOK, err := p.tryParseFunctionAfterTuple(node); err != nil {
				return nil, err
			} else if fnOK {
				node = fn
				if debugEnabled {
					debugf("parseTypeWithOptions: parsed function after tuple, pos=%d\n", p.pos)
				}
			}
		}
	}

	if node.Kind == KindEmptyList && !p.eof() && p.peek() == 't' {
		p.consume()
		node.Kind = KindTuple
		node.Text = ""
		node.Children = nil
		if debugEnabled {
			debugf("parseTypeWithOptions: converted empty list to tuple, pos=%d\n", p.pos)
		}
	}

	if !allowTrailing {
		for {
			if p.matchString("SgXw") || p.matchString("Sg") {
				if debugEnabled {
					debugf("parseTypeWithOptions: optional suffix ahead at pos=%d, skipping function parse\n", p.pos)
				}
				break
			}
			posBefore := p.pos
			fn, ok, err := p.tryParseFunctionType(node)
			if err != nil {
				return nil, err
			}
			if !ok {
				break
			}
			if posBefore == p.pos {
				return nil, fmt.Errorf("function type parse made no progress at %d", p.pos)
			}
			node = fn
			if debugEnabled {
				debugf("parseTypeWithOptions: function type loop iteration, pos=%d\n", p.pos)
			}
		}
		if debugEnabled {
			debugf("parseTypeWithOptions: after function type loop, pos=%d\n", p.pos)
		}

		for {
			for !p.eof() && p.peek() == '_' {
				p.consume()
			}
			if p.eof() || p.peek() == 'I' || p.peek() == 't' || p.peek() == 'y' || p.matchString("SgXw") || p.matchString("Sg") {
				break
			}
			if !canStartStandaloneType(p.peek()) {
				break
			}
			start := p.pos
			extra, err := p.parseTypeWithOptions(true)
			if err != nil {
				p.pos = start
				break
			}
			if p.pos == start {
				break
			}
			if extra != nil {
				node = extra
			}
			if debugEnabled {
				debugf("parseTypeWithOptions: consumed standalone type before impl function, pos=%d\n", p.pos)
			}
		}
	}

	node, err = p.applyOptionalSuffix(node)
	if err != nil {
		return nil, err
	}
	if debugEnabled {
		debugf("parseTypeWithOptions: after applyOptionalSuffix, pos=%d, returning\n", p.pos)
	}

	if !allowTrailing {
		for !p.eof() && p.peek() == 'I' {
			start := p.pos
			p.consume()
			if debugEnabled {
				debugf("parseTypeWithOptions: parsing impl function at pos=%d\n", start)
			}
			implType, implErr := p.parseImplFunctionType()
			if implErr != nil {
				p.pos = start
				return nil, implErr
			}
			node = implType
			p.pushTypeForStack(node)
			if debugEnabled {
				debugf("parseTypeWithOptions: parsed impl function, pos=%d\n", p.pos)
			}
		}
	}

	return node, nil
}

func (p *parser) parsePrimaryType() (result *Node, err error) {
	baseStack := len(p.typeStack)
	defer func() {
		if err != nil {
			if len(p.typeStack) > baseStack {
				p.typeStack = p.typeStack[:baseStack]
			}
			return
		}
		if result != nil {
			p.pushTypeForStack(result)
		}
	}()
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

	if node, ok, err := p.tryParseDependentGenericParam(); err != nil {
		return nil, err
	} else if ok {
		p.pushSubstitution(node)
		// Check for base-first dependent member type: <generic-param> <assoc-name> 'Q' <op>
		if member, memberOk, memberErr := p.tryParseDependentMemberWithBase(node); memberErr != nil {
			return nil, memberErr
		} else if memberOk {
			return member, nil
		}
		return node, nil
	}

	if isDigit(p.peek()) {
		if node, ok, err := p.tryParseNumericSubstitution(); err != nil {
			return nil, err
		} else if ok {
			return node, nil
		}
	}

	// Handle symbolic references first
	if b := p.peek(); b >= 0x01 && b <= 0x1f {
		control := p.consume()
		if p.resolver == nil {
			return nil, fmt.Errorf("symbolic reference encountered without resolver")
		}
		payloadLen := 4
		if control >= 0x18 && control <= 0x1f {
			payloadLen = pointerWidth
		}
		if p.pos+payloadLen > len(p.data) {
			return nil, fmt.Errorf("symbolic reference truncated")
		}
		refIndex := p.pos
		payload := p.data[p.pos : p.pos+payloadLen]
		p.pos += payloadLen
		node, err := p.resolver.ResolveType(control, payload, refIndex)
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

	// Handle 'y' as empty list/tuple marker before trying dependent member type
	if p.peek() == 'y' {
		p.consume()
		node := NewNode(KindEmptyList, "")
		if debugEnabled {
			debugf("parsePrimaryType: parsed empty list at pos=%d\n", p.pos)
		}
		return node, nil
	}

	// Try dependent member types (associated types with Q operator)
	if node, ok, _ := p.tryParseDependentMemberType(); ok {
		return node, nil
	}

	// impl-function-type (found in metadata/closure captures)
	if p.peek() == 'I' {
		p.consume() // consume 'I'
		node, err := p.parseImplFunctionType()
		if err != nil {
			return nil, fmt.Errorf("parseImplFunctionType: %w", err)
		}
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
	if debugEnabled {
		debugf("tryParseStdlibNominal: entry at pos=%d\n", p.pos)
	}
	p.consume() // consume 's'

	names := []string{"Swift"}
	name, err := p.readIdentifier()
	if err != nil {
		p.pos = savePos
		return nil, false, nil
	}
	names = append(names, name)
	if debugEnabled {
		debugf("tryParseStdlibNominal: parsed first identifier %q, pos=%d\n", name, p.pos)
	}

	for !p.eof() {
		if c := p.peek(); c < '0' || c > '9' {
			if debugEnabled {
				debugf("tryParseStdlibNominal: next char %q is not digit, breaking loop at pos=%d\n", c, p.pos)
			}
			break
		}
		if debugEnabled {
			debugf("tryParseStdlibNominal: next char is digit, reading another identifier at pos=%d\n", p.pos)
		}
		next, err := p.readIdentifier()
		if err != nil {
			if debugEnabled {
				debugf("tryParseStdlibNominal: readIdentifier failed: %v, restoring to %d\n", err, savePos)
			}
			p.pos = savePos
			return nil, false, nil
		}
		names = append(names, next)
		if debugEnabled {
			debugf("tryParseStdlibNominal: parsed additional identifier %q, pos=%d, names=%v\n", next, p.pos, names)
		}
	}

	if p.eof() {
		// No kind character - default to Protocol for stdlib types
		// This handles bare references like `s5Error` (Swift.Error)
		if debugEnabled {
			debugf("tryParseStdlibNominal: EOF after identifiers, defaulting to Protocol kind\n")
		}
		node := buildNominal(KindProtocol, names)
		p.pushSubstitution(node)
		return node, true, nil
	}
	kindChar := p.peek()
	nodeKind, ok := nominalTypeKinds[kindChar]
	if !ok {
		// Not a recognized kind character - default to Protocol for stdlib types
		// This handles cases where the type reference doesn't include a kind marker
		if debugEnabled {
			debugf("tryParseStdlibNominal: kind char %q not recognized, defaulting to Protocol\n", kindChar)
		}
		node := buildNominal(KindProtocol, names)
		p.pushSubstitution(node)
		return node, true, nil
	}
	p.consume()
	if debugEnabled {
		debugf("tryParseStdlibNominal: consumed kind char %q, building nominal from names=%v at pos=%d\n", kindChar, names, p.pos)
	}
	node := buildNominal(nodeKind, names)
	p.pushSubstitution(node)
	if debugEnabled {
		debugf("tryParseStdlibNominal: success, returning %s\n", Format(node))
	}
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
		if strings.Contains(node.Text, ".") {
			return strings.Split(node.Text, ".")
		}
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

func (p *parser) tryParseDependentGenericParam() (*Node, bool, error) {
	state := p.saveState()
	depth := 0
	index := 0
	needUnderscore := false
	switch {
	case p.peek() == 'd':
		p.consume()
		dVal, err := p.readNumber()
		if err != nil {
			p.restoreState(state)
			return nil, false, nil
		}
		idxVal, err := p.readNumber()
		if err != nil {
			p.restoreState(state)
			return nil, false, nil
		}
		depth = dVal + 1
		index = idxVal
	case p.peek() == 'z':
		p.consume()
		depth = 0
		index = 0
	case p.peek() == 'x':
		p.consume()
		depth = 0
		index = 0
	case isDigit(p.peek()):
		idxVal, err := p.readNumber()
		if err != nil {
			p.restoreState(state)
			return nil, false, nil
		}
		depth = 0
		index = idxVal + 1
		needUnderscore = true
	default:
		return nil, false, nil
	}

	if needUnderscore {
		if p.eof() || p.peek() != '_' {
			p.restoreState(state)
			return nil, false, nil
		}
		p.consume()
	}

	node := newDependentGenericParamNode(depth, index)
	return node, true, nil
}

func newDependentGenericParamNode(depth, index int) *Node {
	node := NewNode(KindDependentGenericParamType, "")
	node.Append(newIndexNode(depth), newIndexNode(index))
	return node
}

func newIndexNode(val int) *Node {
	n := NewNode(KindIndex, fmt.Sprintf("%d", val))
	return n
}

func (p *parser) tryParseDependentMemberType() (*Node, bool, error) {
	// Quick check: if we're not at a position that could start an identifier, bail out
	if p.eof() || (!isDigit(p.peek()) && p.peek() != '0') {
		return nil, false, nil
	}

	state := p.saveState()
	assoc, err := p.parseAssocTypeNameNode()
	if err != nil {
		p.restoreState(state)
		return nil, false, nil
	}
	if p.eof() || p.peek() != 'Q' {
		p.restoreState(state)
		return nil, false, nil
	}
	p.consume()
	if p.eof() {
		p.restoreState(state)
		return nil, false, nil
	}
	op := p.consume()
	var base *Node
	switch op {
	case 'z':
		base = newDependentGenericParamNode(0, 0)
	case 'y':
		gp, ok, err := p.tryParseDependentGenericParam()
		if err != nil {
			return nil, false, err
		}
		if !ok {
			p.restoreState(state)
			return nil, false, nil
		}
		base = gp
	default:
		p.restoreState(state)
		return nil, false, nil
	}
	member := NewNode(KindDependentMemberType, "")
	member.Append(base, assoc)
	p.pushSubstitution(member)
	return member, true, nil
}

// tryParseDependentMemberWithBase handles the "base-first" encoding: <generic-param> <assoc-name> 'Q' <op>
// This is how Swift encodes dependent member types in parameter contexts.
// The generic param has already been parsed (including any trailing underscore), so we just need
// to parse the associated type name and Q operator.
func (p *parser) tryParseDependentMemberWithBase(base *Node) (*Node, bool, error) {
	state := p.saveState()
	if debugEnabled {
		endPos := state.pos + 20
		if endPos > len(p.data) {
			endPos = len(p.data)
		}
		debugf("tryParseDependentMemberWithBase: starting at pos=%d remaining=%q\n", state.pos, string(p.data[state.pos:endPos]))
	}

	// Parse the associated type name (with word substitutions)
	assoc, err := p.parseAssocTypeNameNode()
	if err != nil {
		if debugEnabled {
			debugf("tryParseDependentMemberWithBase: parseAssocTypeNameNode failed: %v\n", err)
		}
		p.restoreState(state)
		return nil, false, nil
	}

	// Must be followed by 'Q'
	if p.eof() || p.peek() != 'Q' {
		if debugEnabled {
			debugf("tryParseDependentMemberWithBase: not followed by Q at pos=%d, failing\n", p.pos)
		}
		p.restoreState(state)
		return nil, false, nil
	}
	p.consume() // consume 'Q'

	// Parse the operator ('z' or 'y')
	if p.eof() {
		p.restoreState(state)
		return nil, false, nil
	}
	op := p.consume()

	// 'z' means use the already-parsed base, 'y' would mean parse another one (not expected here)
	if op != 'z' {
		if debugEnabled {
			debugf("tryParseDependentMemberWithBase: unexpected operator %q, failing\n", op)
		}
		p.restoreState(state)
		return nil, false, nil
	}

	if debugEnabled {
		debugf("tryParseDependentMemberWithBase: successfully parsed, creating DependentMemberType\n")
	}
	member := NewNode(KindDependentMemberType, "")
	member.Append(base, assoc)
	p.pushSubstitution(member)
	return member, true, nil
}

func (p *parser) parseAssocTypeNameNode() (*Node, error) {
	name, err := p.readAssocIdentifier()
	if err != nil {
		return nil, err
	}
	assoc := NewNode(KindDependentAssociatedTypeRef, name)
	if p.eof() {
		return assoc, nil
	}
	if isDigit(p.peek()) {
		protoName, err := p.readIdentifierNoSubst()
		if err != nil {
			return nil, err
		}
		if err := p.expect('P'); err != nil {
			return nil, err
		}
		proto := NewNode(KindProtocol, protoName)
		assoc.Append(proto)
	}
	return assoc, nil
}

func (p *parser) readAssocIdentifier() (string, error) {
	state := p.saveState()
	if debugEnabled {
		debugf("readAssocIdentifier: saveState pos=%d remaining=%q\n", state.pos, string(p.data[state.pos:]))
	}

	// Associated type names can be encoded with word substitutions OR as literal identifiers.
	// Try word substitutions first (more common for protocol-relative names).
	name, err := p.readIdentifierWithWordSubstitutions()
	if err == nil {
		if !p.eof() && p.peek() == 'Q' {
			if debugEnabled {
				debugf("readAssocIdentifier: parsed identifier %q via word subst path\n", name)
			}
			return name, nil
		}
		// Parsed successfully but not followed by Q - restore and try literal path
		p.restoreState(state)
	} else {
		// Word substitution parsing failed - restore and try literal path
		p.restoreState(state)
	}

	// Try parsing as a literal identifier (length-prefixed)
	if debugEnabled {
		debugf("readAssocIdentifier: trying literal identifier at pos=%d\n", p.pos)
	}
	name, err = p.readIdentifier()
	if err != nil {
		if debugEnabled {
			debugf("readAssocIdentifier: literal identifier parse failed: %v\n", err)
		}
		return "", err
	}
	if !p.eof() && p.peek() != 'Q' {
		if debugEnabled {
			debugf("readAssocIdentifier: literal identifier not followed by Q (have %q), failing\n", p.peek())
		}
		return "", fmt.Errorf("associated type identifier not followed by Q")
	}
	if debugEnabled {
		debugf("readAssocIdentifier: parsed identifier %q via literal path\n", name)
	}
	return name, nil
}

func (p *parser) tryParseNumericSubstitution() (*Node, bool, error) {
	state := p.saveState()
	num, err := p.readNumber()
	if err != nil {
		return nil, false, nil
	}
	if p.eof() || p.peek() != '_' {
		p.restoreState(state)
		return nil, false, nil
	}
	p.consume()
	node, err := p.lookupSubstitution(num)
	if err != nil {
		p.restoreState(state)
		return nil, false, nil
	}
	return node, true, nil
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
			if bytes.IndexByte(p.data[p.pos:], 'G') == -1 {
				return current, nil
			}
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

		arg, err := p.parseTypeAllowTrailing()
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

	if debugEnabled {
		debugf("parseBoundGeneric: base=%s args=%d\n", Format(base), len(args))
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
	if p.eof() {
		return nil, false, nil
	}

	if p.peek() == 'I' {
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
		return nil, false, nil
	}

	// At this point, we've successfully parsed parameters onto the stack/tree
	// We must NOT rewind even if subsequent checks fail, because the parameters
	// are real and have consumed input.

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
	labelStart := p.pos

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
		debugf("parseFunctionInput: start=%d remaining=%q pendingLen=%d floor=%d next=%q next2=%q\n", labelStart, string(p.data[labelStart:]), len(p.pending), p.pendingFloor, next, next2)
	}

	// Empty tuple is encoded as 'y' (optionally repeated). Accept single 'y'.
	if p.peek() == 'y' {
		p.consume()
		if !p.eof() && p.peek() == 'y' {
			p.consume()
		}
		tuple := NewNode(KindTuple, "")
		return tuple, true, nil
	}

	// Try to skip parameter label if present
	p.skipParameterLabel()

	// If we have 'y' after the label, parse as tuple
	if !p.eof() && p.peek() == 'y' {
		p.pushPendingScope()
		tuple, err := p.parseParameterTuple()
		p.popPendingScope()
		if err != nil {
			// Tuple parsing failed - restore to before we tried to skip label
			p.pos = labelStart
			return nil, false, nil
		}
		if debugEnabled {
			debugf("parseFunctionInput: parsed tuple node=%s pos=%d remaining=%q\n", Format(tuple), p.pos, string(p.data[p.pos:]))
		}
		return tuple, true, nil
	}

	// Try to parse as a single type
	node, err := p.parseTypeWithOptions(true)
	if err != nil {
		// Type parsing failed - restore to before we tried to skip label
		p.pos = labelStart
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

func (p *parser) skipParameterLabel() {
	if p.eof() || p.peek() != '_' {
		return
	}
	if p.pos+1 >= len(p.data) || !isDigit(p.data[p.pos+1]) {
		return
	}
	save := p.pos
	p.consume() // underscore
	if debugEnabled {
		debugf("skipParameterLabel: consumed '_' at %d\n", save)
	}
	if _, err := p.readIdentifierNoSubst(); err != nil {
		p.pos = save
		return
	}
	if debugEnabled {
		nxt := byte(0)
		if !p.eof() {
			nxt = p.peek()
		}
		debugf("skipParameterLabel: new pos=%d next=%q\n", p.pos, nxt)
	}
}

func (p *parser) parseParameterTuple() (*Node, error) {
	start := p.pos
	if p.eof() || p.peek() != 'y' {
		return nil, fmt.Errorf("parameter tuple must start with 'y'")
	}
	p.consume()
	tuple := NewNode(KindTuple, "")
	frame := p.pushNodeFrame()
	success := false
	defer func() {
		if !success {
			p.discardNodeFrame(frame)
		}
	}()
	for {
		if p.eof() {
			return nil, fmt.Errorf("unterminated parameter tuple starting at %d", start)
		}
		if debugEnabled {
			debugf("parseParameterTuple: pos=%d char=%q remaining=%q\n", p.pos, p.peek(), string(p.data[p.pos:]))
		}
		if p.peek() == '_' {
			p.consume()
			continue
		}
		if p.peek() == 't' {
			p.consume()
			break
		}
		elem, err := p.parseParameterElement()
		if err != nil {
			return nil, err
		}
		if !p.eof() && p.peek() == 'z' {
			p.consume()
			wrapped := NewNode(KindInOut, "")
			wrapped.Append(elem)
			elem = wrapped
		}
		p.pushNode(elem)
	}
	elems := p.popNodesSince(frame)
	for _, el := range elems {
		tuple.Append(el)
	}
	success = true
	return tuple, nil
}

func (p *parser) parseParameterElement() (*Node, error) {
	// In parameter context, we need to handle sequences like "01_A5CTypeQz"
	// where 01_ is a dependent generic param that gets combined with a dependent member type.
	// The C++ demangler uses a stack; we simulate this with lookahead.

	// Check if we're starting with a dependent generic param followed by identifier+Q
	if isDigit(p.peek()) || p.peek() == 'x' || p.peek() == 'z' || p.peek() == 'd' {
		state := p.saveState()

		// Try to parse a dependent generic param
		gpNode, gpOk, gpErr := p.tryParseDependentGenericParam()
		if gpErr != nil {
			p.restoreState(state)
		} else if gpOk {
			// Check if followed by an identifier + Q (dependent member type pattern)
			checkPos := p.pos
			if !p.eof() && (isAlpha(p.peek()) || isDigit(p.peek())) {
				// Try to parse the dependent member type
				if node, ok, err := p.tryParseDependentAssocElement(); err == nil && ok {
					// Success! The generic param was context, and we got the member type
					return node, nil
				}
			}
			// Not a dependent member pattern, restore and return the generic param
			p.pos = checkPos
			return gpNode, nil
		}
		p.restoreState(state)
	}

	// Try standard dependent assoc element (A5CTypeQz without prefix)
	if node, ok, err := p.tryParseDependentAssocElement(); err != nil {
		return nil, err
	} else if ok {
		return node, nil
	}

	// Standard type parsing
	return p.parseTypeWithOptions(true)
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func canStartStandaloneType(b byte) bool {
	if b == 0 {
		return false
	}
	if b >= 0x01 && b <= 0x1f {
		return true
	}
	if b >= '0' && b <= '9' {
		return true
	}
	if b >= 'a' && b <= 'z' {
		if b == 't' || b == 'y' {
			return false
		}
		return true
	}
	if b >= 'A' && b <= 'Z' {
		return true
	}
	if b == '$' {
		return true
	}
	return false
}

func (p *parser) tryParseDependentAssocElement() (*Node, bool, error) {
	state := p.saveState()
	assoc, err := p.parseAssocTypeNameNode()
	if err != nil {
		p.restoreState(state)
		return nil, false, nil
	}
	if err := p.expect('Q'); err != nil {
		p.restoreState(state)
		return nil, false, nil
	}
	if p.eof() {
		p.restoreState(state)
		return nil, false, nil
	}
	op := p.consume()
	var base *Node
	switch op {
	case 'z':
		base = newDependentGenericParamNode(0, 0)
	case 'y':
		gp, ok, err := p.tryParseDependentGenericParam()
		if err != nil {
			return nil, false, err
		}
		if !ok {
			p.restoreState(state)
			return nil, false, nil
		}
		base = gp
	default:
		p.restoreState(state)
		return nil, false, nil
	}
	member := NewNode(KindDependentMemberType, "")
	member.Append(base, assoc)
	return member, true, nil
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

		posBefore := p.pos
		elem, err := p.parseTypeWithOptions(true)
		if err != nil {
			p.pos = savePos
			return node, false, nil
		}
		if p.pos == posBefore {
			panic("infinite loop detected in recursive tuple parse")
		}
		if !p.eof() && p.peek() == 'z' {
			p.consume()
			wrapped := NewNode(KindInOut, "")
			wrapped.Append(elem)
			elem = wrapped
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

// parseImplFunctionType parses an implementation function type (metadata encoding).
// Grammar: impl-function-type ::= type* 'I' FUNC-ATTRIBUTES '_'
// Phase 1: Basic support for escaping, callee convention, and terminator.
// Full implementation will add: generic signatures, substitutions, async, sendable,
// parameters, results, etc.
//
// ref: https://github.com/apple/swift/blob/main/docs/ABI/Mangling.rst#function-signature
// ref: OPC/swift-main/lib/Demangling/Demangler.cpp::demangleImplFunctionType
func (p *parser) parseImplFunctionType() (*Node, error) {
	// Note: 'I' already consumed by caller

	// Create the ImplFunctionType node
	implType := NewNode(KindImplFunctionType, "")

	// Phase 1: Parse minimal attributes for closure captures
	// Format: I + [e] + (y|g|x|t) + [other attributes] + _

	// 1. Check for escaping ('e')
	if p.peek() == 'e' {
		p.consume()
		escaping := NewNode(KindImplEscaping, "")
		implType.Append(escaping)
		if debugEnabled {
			debugf("parseImplFunctionType: parsed @escaping at pos=%d\n", p.pos)
		}
	}

	// Isolation attribute ('A')
	if p.peek() == 'A' {
		p.consume()
		implType.Append(NewNode(KindImplFunctionAttribute, "@isolated(any)"))
		if debugEnabled {
			debugf("parseImplFunctionType: parsed @isolated(any) at pos=%d\n", p.pos)
		}
	}

	// 2. Parse callee convention (REQUIRED)
	// CALLEE-CONVENTION ::= 'y' | 'g' | 'x' | 't'
	var convAttr string
	switch p.peek() {
	case 'y':
		convAttr = "@callee_unowned"
		p.consume()
	case 'g':
		convAttr = "@callee_guaranteed"
		p.consume()
	case 'x':
		convAttr = "@callee_owned"
		p.consume()
	case 't':
		convAttr = "@convention(thin)"
		p.consume()
	default:
		return nil, fmt.Errorf("expected callee convention (y/g/x/t) at pos=%d, got %q", p.pos, p.peek())
	}

	convention := NewNode(KindImplConvention, convAttr)
	implType.Append(convention)

	if debugEnabled {
		debugf("parseImplFunctionType: parsed convention %s at pos=%d\n", convAttr, p.pos)
	}

	// 3. Parse optional function convention (FUNC-REPRESENTATION)
	// FUNC-REPRESENTATION ::= 'B' | 'C' | 'M' | 'J' | 'K' | 'W' | 'zB' C-TYPE | 'zC' C-TYPE
	var funcConv string
	var hasClangType bool
	switch p.peek() {
	case 'B':
		funcConv = "block"
		p.consume()
	case 'C':
		funcConv = "c"
		p.consume()
	case 'z':
		p.consume()
		switch p.peek() {
		case 'B':
			funcConv = "block"
			hasClangType = true
			p.consume()
		case 'C':
			funcConv = "c"
			hasClangType = true
			p.consume()
		default:
			// Not a function convention, backtrack
			p.pos--
		}
	case 'M':
		funcConv = "method"
		p.consume()
	case 'J':
		funcConv = "objc_method"
		p.consume()
	case 'K':
		funcConv = "closure"
		p.consume()
	case 'W':
		funcConv = "witness_method"
		p.consume()
	}

	if funcConv != "" {
		funcAttrNode := NewNode(KindImplFunctionConvention, "")
		funcAttrNode.Append(NewNode(KindImplFunctionConventionName, funcConv))
		if hasClangType {
			// Phase 2: Skip clang type for now
			// Phase 3+ will implement demangleClangType()
			// Just consume until we hit a known next character
			if debugEnabled {
				debugf("parseImplFunctionType: skipping clang type at pos=%d (Phase 2)\n", p.pos)
			}
		}
		implType.Append(funcAttrNode)
		if debugEnabled {
			debugf("parseImplFunctionType: parsed function convention %s at pos=%d\n", funcConv, p.pos)
		}
	}

	// 4. Parse optional coroutine kind
	// COROUTINE-KIND ::= 'A' | 'I' | 'G'
	var coroAttr string
	switch p.peek() {
	case 'A':
		coroAttr = "yield_once"
		p.consume()
	case 'I':
		coroAttr = "yield_once_2"
		p.consume()
	case 'G':
		coroAttr = "yield_many"
		p.consume()
	}
	if coroAttr != "" {
		implType.Append(NewNode(KindImplCoroutineKind, coroAttr))
		if debugEnabled {
			debugf("parseImplFunctionType: parsed coroutine kind %s at pos=%d\n", coroAttr, p.pos)
		}
	}

	// 5. Parse optional sendable attribute
	if p.peek() == 'h' {
		p.consume()
		implType.Append(NewNode(KindImplFunctionAttribute, "@Sendable"))
		if debugEnabled {
			debugf("parseImplFunctionType: parsed @Sendable at pos=%d\n", p.pos)
		}
	}

	// 6. Parse optional async attribute
	if p.peek() == 'H' {
		p.consume()
		implType.Append(NewNode(KindImplFunctionAttribute, "@async"))
		if debugEnabled {
			debugf("parseImplFunctionType: parsed @async at pos=%d\n", p.pos)
		}
	}

	// 7. Parse optional sending result attribute (Swift 6.0+)
	if p.peek() == 'T' {
		p.consume()
		implType.Append(NewNode(KindImplSendingResult, ""))
		if debugEnabled {
			debugf("parseImplFunctionType: parsed sending result at pos=%d\n", p.pos)
		}
	}

	// Phase 3: Parse parameters, results, yields, error result

	// 8. Parse parameters (IMPL-PARAMETER*)
	// Parameters are identified by convention characters: i,c,l,b,n,X,x,g,e,y,v,p,m
	var paramsAndResults []*Node
	for {
		paramConv := p.parseImplParamConvention()
		if paramConv == "" {
			break // No more parameters
		}
		param := NewNode(KindImplParameter, "")
		param.Append(NewNode(KindImplConvention, paramConv))

		// TODO Phase 3.2: Parse optional parameter attributes (differentiability, sending, isolated, implicit_leading)

		paramsAndResults = append(paramsAndResults, param)
		implType.Append(param)

		if debugEnabled {
			debugf("parseImplFunctionType: parsed parameter %s at pos=%d\n", paramConv, p.pos)
		}
	}

	// 9. Parse results (IMPL-RESULT*)
	// Results are identified by convention characters: r,o,d,u,a,k (and l,g,m in result context)
	for {
		resultConv := p.parseImplResultConvention()
		if resultConv == "" {
			break // No more results
		}
		result := NewNode(KindImplResult, "")
		result.Append(NewNode(KindImplConvention, resultConv))

		// TODO Phase 3.2: Parse optional result attributes (differentiability)

		paramsAndResults = append(paramsAndResults, result)
		implType.Append(result)

		if debugEnabled {
			debugf("parseImplFunctionType: parsed result %s at pos=%d\n", resultConv, p.pos)
		}
	}

	// 10. Parse yields (Y + IMPL-YIELD)
	// TODO Phase 3.2: Implement yield parsing if needed

	// 11. Parse error result (z + IMPL-ERROR-RESULT)
	// TODO Phase 3.2: Implement error result parsing if needed

	// 12. Expect terminator '_'
	if p.eof() || p.peek() != '_' {
		return nil, fmt.Errorf("expected '_' terminator at pos=%d, got %q", p.pos, p.peek())
	}
	p.consume() // consume '_'

	if debugEnabled {
		debugf("parseImplFunctionType: parsed terminator at pos=%d\n", p.pos)
	}

	// 13. Attach previously parsed types for each parameter/result.
	if len(paramsAndResults) > 0 {
		if debugEnabled {
			debugf("parseImplFunctionType: attaching %d prior types\n", len(paramsAndResults))
		}
		popped, err := p.popTypeNodes(len(paramsAndResults))
		if err != nil {
			return nil, err
		}
		for idx := len(paramsAndResults) - 1; idx >= 0; idx-- {
			popIdx := len(paramsAndResults) - 1 - idx
			typ := popped[popIdx]
			if typ == nil {
				return nil, fmt.Errorf("impl function missing type for param/result %d", popIdx)
			}
			paramsAndResults[idx].Append(typ)
			if debugEnabled {
				debugf("parseImplFunctionType: attached prior type to param/result %d\n", idx)
			}
		}
	}

	// Wrap in Type node (matches upstream behavior)
	typeNode := NewNode(KindType, "")
	typeNode.Append(implType)

	return typeNode, nil
}

// parseImplParamConvention parses a parameter convention character.
// Returns the convention string or empty string if no parameter convention found.
// ref: OPC/swift-main/lib/Demangling/Demangler.cpp::demangleImplParamConvention
func (p *parser) parseImplParamConvention() string {
	switch p.peek() {
	case 'i':
		p.consume()
		return "@in"
	case 'c':
		p.consume()
		return "@in_constant"
	case 'l':
		p.consume()
		return "@inout"
	case 'b':
		p.consume()
		return "@inout_aliasable"
	case 'n':
		p.consume()
		return "@in_guaranteed"
	case 'X':
		p.consume()
		return "@in_cxx"
	case 'x':
		p.consume()
		return "@owned"
	case 'g':
		p.consume()
		return "@guaranteed"
	case 'e':
		p.consume()
		return "@deallocating"
	case 'y':
		p.consume()
		return "@unowned"
	case 'v':
		p.consume()
		return "@pack_owned"
	case 'p':
		p.consume()
		return "@pack_guaranteed"
	case 'm':
		p.consume()
		return "@pack_inout"
	default:
		return ""
	}
}

// parseImplResultConvention parses a result convention character.
// Returns the convention string or empty string if no result convention found.
// ref: OPC/swift-main/lib/Demangling/Demangler.cpp::demangleImplResultConvention
func (p *parser) parseImplResultConvention() string {
	switch p.peek() {
	case 'r':
		p.consume()
		return "@out"
	case 'o':
		p.consume()
		return "@owned"
	case 'd':
		p.consume()
		return "@unowned"
	case 'u':
		p.consume()
		return "@unowned_inner_pointer"
	case 'a':
		p.consume()
		return "@autoreleased"
	case 'k':
		p.consume()
		return "@pack_out"
	// Note: 'l', 'g', 'm' are shared with parameters but in result context they mean:
	// 'l' = @guaranteed_address (not @inout)
	// 'g' = @guaranteed (same as parameter)
	// 'm' = @inout (same as parameter but valid in result context)
	// We can't distinguish context here, so we only handle unambiguous result conventions
	default:
		return ""
	}
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
