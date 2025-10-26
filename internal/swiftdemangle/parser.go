package swiftdemangle

import (
	"fmt"
	"strings"
)

var accessorDisplay = map[string]string{
	"g":  "getter",
	"s":  "setter",
	"M":  "modify",
	"x":  "modify2",
	"m":  "materializeForSet",
	"r":  "read",
	"y":  "read2",
	"i":  "init",
	"b":  "borrow",
	"z":  "mutate",
	"G":  "globalGetter",
	"w":  "willSet",
	"W":  "didSet",
	"aO": "owningMutableAddressor",
	"ao": "nativeOwningMutableAddressor",
	"aP": "nativePinningMutableAddressor",
	"au": "unsafeMutableAddressor",
	"lO": "owningAddressor",
	"lo": "nativeOwningAddressor",
	"lp": "nativePinningAddressor",
	"lu": "unsafeAddressor",
}

// SymbolicReferenceResolver resolves symbolic reference offsets found in mangled
// strings. Implementations must interpret the offset relative to the address of
// the reference site and return a preconstructed node representing the target
// context or type.
type SymbolicReferenceResolver interface {
	ResolveType(control byte, offset int32, refIndex int) (*Node, error)
}

type parser struct {
	data          []byte
	pos           int
	resolver      SymbolicReferenceResolver
	subst         []*Node
	context       *Node
	pending       []*Node
	pendingFloor  int
	pendingScopes []int
	words         []string
	nodeStack     []*Node // Lightweight stack for function params and dependent member types
}

func newParser(data []byte, resolver SymbolicReferenceResolver) *parser {
	return &parser{
		data:     data,
		resolver: resolver,
		words:    make([]string, 0, maxIdentifierWords),
	}
}

const maxIdentifierWords = 26

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

// Node stack helpers for stack-based parsing (function params, dependent member types)
func (p *parser) pushNode(n *Node) {
	p.nodeStack = append(p.nodeStack, n)
}

func (p *parser) popNode() *Node {
	if len(p.nodeStack) == 0 {
		return nil
	}
	n := p.nodeStack[len(p.nodeStack)-1]
	p.nodeStack = p.nodeStack[:len(p.nodeStack)-1]
	return n
}

func (p *parser) peekNode() *Node {
	if len(p.nodeStack) == 0 {
		return nil
	}
	return p.nodeStack[len(p.nodeStack)-1]
}

func (p *parser) pushNodeFrame() int {
	return len(p.nodeStack)
}

func (p *parser) discardNodeFrame(frame int) {
	if frame < 0 || frame > len(p.nodeStack) {
		return
	}
	p.nodeStack = p.nodeStack[:frame]
}

func (p *parser) popNodesSince(frame int) []*Node {
	if frame < 0 || frame > len(p.nodeStack) {
		return nil
	}
	nodes := append([]*Node(nil), p.nodeStack[frame:]...)
	p.nodeStack = p.nodeStack[:frame]
	return nodes
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
	return p.readIdentifierInternal(true)
}

func (p *parser) readIdentifierNoSubst() (string, error) {
	return p.readIdentifierInternal(false)
}

func (p *parser) readIdentifierInternal(addSubst bool) (string, error) {
	text, err := p.readIdentifierText()
	if err != nil {
		return "", err
	}
	if text == "" {
		return "", fmt.Errorf("empty identifier")
	}
	if addSubst {
		ident := NewNode(KindIdentifier, text)
		p.pushSubstitution(ident)
	}
	return text, nil
}

func (p *parser) readIdentifierText() (string, error) {
	if p.eof() {
		return "", fmt.Errorf("unexpected end while reading identifier")
	}
	switch {
	case p.peek() == '0':
		if p.pos+1 >= len(p.data) {
			return "", fmt.Errorf("unterminated identifier prefix at position %d", p.pos)
		}
		if p.data[p.pos+1] == '0' {
			p.consume()
			p.consume()
			return p.readPunycodeIdentifierText()
		}
		p.consume()
		return p.readIdentifierWithWordSubstitutions()
	case isDigit(p.peek()):
		return p.readLiteralIdentifierText()
	case isUpperLetter(p.peek()):
		if text, ok := p.readWordSubstitutionLiteral(); ok {
			return text, nil
		}
		return "", fmt.Errorf("identifier starting with uppercase letter %q requires length prefix", p.peek())
	default:
		return "", fmt.Errorf("invalid identifier prefix %q at position %d", p.peek(), p.pos)
	}
}

func (p *parser) readLiteralIdentifierText() (string, error) {
	chunk, err := p.readIdentifierChunk()
	if err != nil {
		return "", err
	}
	p.recordWordsFromLiteral(chunk)
	return chunk, nil
}

func (p *parser) readWordSubstitutionLiteral() (string, bool) {
	for idx := len(p.words) - 1; idx >= 0; idx-- {
		candidate := p.words[idx]
		if strings.HasPrefix(candidate, string(p.data[p.pos:])) {
			p.pos += len(candidate)
			return candidate, true
		}
	}
	return "", false
}

func (p *parser) readIdentifierWithWordSubstitutions() (string, error) {
	var out strings.Builder
	hasWordSubsts := true
	for {
		for hasWordSubsts && !p.eof() && isLetter(p.peek()) {
			c := p.consume()
			idx := 0
			if isLowerLetter(c) {
				idx = int(c - 'a')
			} else if isUpperLetter(c) {
				idx = int(c - 'A')
				hasWordSubsts = false
			} else {
				return "", fmt.Errorf("invalid word substitution marker %q", c)
			}
			if idx >= len(p.words) {
				return "", fmt.Errorf("word substitution index %d out of range (have %d words)", idx, len(p.words))
			}
			if debugEnabled {
				debugf("readIdentifierWithWordSubstitutions: subst [%d]=%q\n", idx, p.words[idx])
			}
			out.WriteString(p.words[idx])
		}

		if p.eof() {
			break
		}
		if p.peek() == '0' {
			p.consume()
			break
		}

		chunk, err := p.readIdentifierChunk()
		if err != nil {
			return "", err
		}
		if chunk == "" {
			return "", fmt.Errorf("empty identifier chunk")
		}
		if debugEnabled {
			debugf("readIdentifierWithWordSubstitutions: chunk=%q words before=%d\n", chunk, len(p.words))
		}
		out.WriteString(chunk)
		p.recordWordsFromLiteral(chunk)
		if debugEnabled {
			debugf("readIdentifierWithWordSubstitutions: words after=%d (%v)\n", len(p.words), p.words)
		}

		if !hasWordSubsts {
			break
		}
	}

	if out.Len() == 0 {
		return "", fmt.Errorf("empty identifier")
	}
	return out.String(), nil
}

func (p *parser) readPunycodeIdentifierText() (string, error) {
	length, err := p.readNumber()
	if err != nil {
		return "", err
	}
	if length <= 0 {
		return "", fmt.Errorf("punycode identifier length must be >0, got %d", length)
	}
	if p.eof() {
		return "", fmt.Errorf("unexpected end inside punycode identifier")
	}
	if p.peek() == '_' {
		p.consume()
	}
	if p.pos+length > len(p.data) {
		return "", fmt.Errorf("punycode identifier exceeds input length")
	}
	start := p.pos
	p.pos += length
	encoded := string(p.data[start:p.pos])
	decoded, err := decodeSwiftPunycode(encoded)
	if err != nil {
		return "", err
	}
	p.recordWordsFromLiteral(decoded)
	return decoded, nil
}

func (p *parser) readIdentifierChunk() (string, error) {
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

func (p *parser) recordWordsFromLiteral(lit string) {
	if len(lit) == 0 || len(p.words) >= maxIdentifierWords {
		return
	}
	wordStart := -1
	for i := 0; i <= len(lit); i++ {
		var curr byte
		if i < len(lit) {
			curr = lit[i]
		} else {
			curr = 0
		}
		if wordStart >= 0 && i > 0 {
			prev := lit[i-1]
			if isWordEndChar(curr, prev) {
				if i-wordStart >= 2 && len(p.words) < maxIdentifierWords {
					p.words = append(p.words, lit[wordStart:i])
				}
				wordStart = -1
			}
		}
		if i < len(lit) && wordStart < 0 && isWordStartChar(curr) {
			wordStart = i
		}
	}
}

func decodeSwiftPunycode(encoded string) (string, error) {
	if encoded == "" {
		return "", fmt.Errorf("empty punycode payload")
	}
	var translated strings.Builder
	translated.Grow(len(encoded))
	for i := 0; i < len(encoded); i++ {
		ch := encoded[i]
		if ch >= 'A' && ch <= 'J' {
			translated.WriteByte(byte('0' + (ch - 'A')))
		} else {
			translated.WriteByte(ch)
		}
	}
	normalized := strings.ReplaceAll(strings.ToLower(translated.String()), "_", "-")
	decoded, err := decodePunycode(normalized)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

const (
	punycodeBase        = 36
	punycodeTmin        = 1
	punycodeTmax        = 26
	punycodeSkew        = 38
	punycodeDamp        = 700
	punycodeInitialBias = 72
	punycodeInitialN    = 128
	punycodeDelimiter   = '-'
)

func decodePunycode(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty punycode string")
	}
	n := punycodeInitialN
	i := 0
	bias := punycodeInitialBias
	var output []rune
	pos := 0
	if idx := strings.LastIndexByte(input, punycodeDelimiter); idx >= 0 {
		for _, r := range input[:idx] {
			if r >= 0x80 {
				return "", fmt.Errorf("non-basic code point %q in punycode prefix", r)
			}
			output = append(output, r)
		}
		pos = idx + 1
	}
	for pos < len(input) {
		oldi := i
		w := 1
		for k := punycodeBase; ; k += punycodeBase {
			if pos >= len(input) {
				return "", fmt.Errorf("truncated punycode input")
			}
			digit, ok := decodePunycodeDigit(input[pos])
			if !ok {
				return "", fmt.Errorf("invalid punycode digit %q", input[pos])
			}
			pos++
			i += digit * w
			var t int
			switch {
			case k <= bias+punycodeTmin:
				t = punycodeTmin
			case k >= bias+punycodeTmax:
				t = punycodeTmax
			default:
				t = k - bias
			}
			if digit < t {
				break
			}
			w *= punycodeBase - t
		}
		bias = adaptPunycodeBias(i-oldi, len(output)+1, oldi == 0)
		n += i / (len(output) + 1)
		i %= len(output) + 1
		r := rune(n)
		if int(r) != n {
			return "", fmt.Errorf("punycode rune overflow")
		}
		output = append(output, 0)
		copy(output[i+1:], output[i:])
		output[i] = r
		i++
	}
	return string(output), nil
}

func decodePunycodeDigit(b byte) (int, bool) {
	switch {
	case b >= 'a' && b <= 'z':
		return int(b - 'a'), true
	case b >= 'A' && b <= 'Z':
		return int(b - 'A'), true
	case b >= '0' && b <= '9':
		return int(b-'0') + 26, true
	default:
		return 0, false
	}
}

func adaptPunycodeBias(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punycodeDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((punycodeBase-punycodeTmin)*punycodeTmax)/2 {
		delta /= punycodeBase - punycodeTmin
		k += punycodeBase
	}
	return k + (punycodeBase-punycodeTmin+1)*delta/(delta+punycodeSkew)
}

type parserState struct {
	pos        int
	substLen   int
	pendingLen int
}

func (p *parser) saveState() parserState {
	return parserState{
		pos:        p.pos,
		substLen:   len(p.subst),
		pendingLen: len(p.pending),
	}
}

func (p *parser) restoreState(state parserState) {
	if debugEnabled {
		debugf("restoreState: from pos=%d to pos=%d (delta=%d)\n", p.pos, state.pos, state.pos-p.pos)
	}
	p.pos = state.pos
	if len(p.subst) > state.substLen {
		p.subst = p.subst[:state.substLen]
	}
	if len(p.pending) > state.pendingLen {
		p.pending = p.pending[:state.pendingLen]
	}
}

func (p *parser) pushSubstitution(n *Node) {
	if n == nil {
		return
	}
	if debugEnabled {
		debugf("pushSubstitution[%d]=%s\n", len(p.subst), Format(n))
	}
	p.subst = append(p.subst, n)
}

func (p *parser) pushPendingNode(n *Node, copies int) {
	if n == nil {
		return
	}
	if copies <= 0 {
		copies = 1
	}
	for i := 0; i < copies; i++ {
		if debugEnabled {
			debugf("queued pending node %s\n", Format(n))
		}
		p.pending = append(p.pending, n.Clone())
	}
}

func (p *parser) pushPendingScope() {
	p.pendingScopes = append(p.pendingScopes, p.pendingFloor)
	p.pendingFloor = len(p.pending)
}

func (p *parser) popPendingScope() {
	if len(p.pendingScopes) == 0 {
		p.pendingFloor = 0
		return
	}
	prev := p.pendingScopes[len(p.pendingScopes)-1]
	p.pendingScopes = p.pendingScopes[:len(p.pendingScopes)-1]
	if prev < 0 {
		prev = 0
	}
	if prev > len(p.pending) {
		prev = len(p.pending)
	}
	p.pendingFloor = prev
}

func (p *parser) lookupSubstitution(index int) (*Node, error) {
	if index >= 0 && index < len(p.subst) {
		return p.subst[index], nil
	}
	if p.context != nil && index >= len(p.subst) {
		return p.context, nil
	}
	return nil, fmt.Errorf("invalid substitution index %d (have %d)", index, len(p.subst))
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

func isLowerLetter(b byte) bool {
	return b >= 'a' && b <= 'z'
}

func isUpperLetter(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

func isLetter(b byte) bool {
	return isLowerLetter(b) || isUpperLetter(b)
}

func isWordStartChar(b byte) bool {
	return !isDigit(b) && b != '_' && b != 0
}

func isWordEndChar(next, prev byte) bool {
	if next == '_' || next == 0 {
		return true
	}
	if !isUpperLetter(prev) && isUpperLetter(next) {
		return true
	}
	return false
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isContextKind(b byte) bool {
	switch b {
	case 'C', 'V', 'O', 'E', 'P', 'N', 'B', 'I', 'G', 'M', 'T':
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

	if p.eof() {
		return nil, fmt.Errorf("missing symbol body")
	}

	root, err := p.parseSymbolBody()
	if err != nil {
		return nil, err
	}

	node, err := p.applySymbolSuffixes(root)
	if err != nil {
		return nil, err
	}
	return node, nil
}

func (p *parser) parseSymbolBody() (*Node, error) {
	// Symbols can start with:
	// 1. A digit (regular module): parse with parseSymbolWithModule
	// 2. 's' (stdlib module): also parse with parseSymbolWithModule
	// 3. Other: parse as special symbol (pure type)
	if isDigit(p.peek()) || p.peek() == 's' {
		return p.parseSymbolWithModule()
	}
	return p.parseSpecialSymbol()
}

func (p *parser) parseSymbolWithModule() (*Node, error) {
	// Handle stdlib marker 's' specially
	var moduleName string
	var moduleNode *Node
	if p.peek() == 's' {
		p.consume() // consume 's'
		moduleName = "Swift"
		moduleNode = NewNode(KindModule, moduleName)
		p.pushSubstitution(moduleNode)
	} else {
		// Regular module name (digit-prefixed identifier)
		name, err := p.readIdentifier()
		if err != nil {
			return nil, fmt.Errorf("failed to read module: %w", err)
		}
		moduleName = name
		moduleNode = NewNode(KindModule, moduleName)
		p.pushSubstitution(moduleNode)
	}

	var contextNames []string
	var currentContext *Node
	for {
		savePos := p.pos
		if debugEnabled {
			debugf("parseSymbolWithModule: context loop iteration at pos=%d remaining=%q\n", p.pos, string(p.data[p.pos:]))
		}
		name, err := p.readIdentifier()
		if err != nil {
			if debugEnabled {
				debugf("parseSymbolWithModule: readIdentifier failed: %v, breaking at pos=%d\n", err, p.pos)
			}
			p.pos = savePos
			break
		}
		if debugEnabled {
			debugf("parseSymbolWithModule: read identifier %q, pos now %d\n", name, p.pos)
		}
		if p.eof() {
			if debugEnabled {
				debugf("parseSymbolWithModule: EOF after identifier, breaking\n")
			}
			p.pos = savePos
			break
		}
		kind := p.peek()
		if !isContextKind(kind) {
			if debugEnabled {
				debugf("parseSymbolWithModule: byte %q is not context kind, breaking and restoring to pos=%d\n", kind, savePos)
			}
			p.pos = savePos
			break
		}
		p.consume()
		if debugEnabled {
			debugf("parseSymbolWithModule: consumed context kind %q, pos now %d\n", kind, p.pos)
		}

		pathNames := append([]string{moduleName}, append(contextNames, name)...)
		node := buildNominal(nominalTypeKinds[kind], pathNames)
		contextNames = append(contextNames, name)
		p.pushSubstitution(node)
		currentContext = node
	}
	if currentContext != nil {
		p.context = currentContext
	}

	if debugEnabled {
		debugf("parseSymbolWithModule: done with context loop, calling parseSymbolEntity at pos=%d\n", p.pos)
	}
	return p.parseSymbolEntity(moduleName, contextNames, currentContext)
}

func (p *parser) parseSpecialSymbol() (*Node, error) {
	base, err := p.parseType()
	if err != nil {
		return nil, err
	}
	if !p.eof() && isDigit(p.peek()) {
		prefix := Format(base)
		return p.parseSymbolEntity(prefix, nil, base)
	}
	return base, nil
}

func (p *parser) parseSymbolEntity(moduleName string, contextNames []string, base *Node) (*Node, error) {
	start := p.pos
	state := p.saveState()
	startPos := p.pos
	if node, ok, err := p.tryParseConstructorSpec(moduleName, contextNames, base); ok {
		return node, err
	}
	// Only restore if position hasn't advanced (no input consumed)
	if p.pos == startPos {
		p.restoreState(state)
	}

	state = p.saveState()
	startPos = p.pos
	if node, ok, err := p.tryParseFunctionSpec(moduleName, contextNames); ok {
		return node, err
	}
	// Only restore if position hasn't advanced
	if p.pos == startPos {
		p.restoreState(state)
	}

	state = p.saveState()
	startPos = p.pos
	if node, ok, err := p.tryParseVariableSpec(moduleName, contextNames); ok {
		return node, err
	}
	// Only restore if position hasn't advanced
	if p.pos == startPos {
		p.restoreState(state)
	}

	if base != nil {
		return base, nil
	}
	return nil, fmt.Errorf("unsupported entity at position %d", start)
}

func (p *parser) tryParseFunctionSpec(moduleName string, contextNames []string) (*Node, bool, error) {
	startState := p.saveState()
	if debugEnabled {
		debugf("tryParseFunctionSpec: module=%s contexts=%v pos=%d\n", moduleName, contextNames, p.pos)
	}
	name, err := p.readEntityName()
	if err != nil {
		p.restoreState(startState)
		return nil, false, nil
	}
	labels, err := p.parseLabelList()
	if err != nil {
		p.restoreState(startState)
		return nil, false, err
	}
	if debugEnabled {
		debugf("tryParseFunctionSpec: invoking parseFunctionSignature at pos=%d\n", p.pos)
	}
	params, resultType, async, throws, err := p.parseFunctionSignature()
	if err != nil {
		p.restoreState(startState)
		return nil, false, err
	}

	// IMPORTANT: Once parseFunctionSignature succeeds, we must NOT restore state even if
	// the 'F' check fails. The signature parsing consumed input and may have pushed nodes/substitutions.
	if err := p.expect('F'); err != nil {
		// Not a function entity - return ok=false but DON'T restore state
		return nil, false, nil
	}
	node := buildFunctionNode(moduleName, contextNames, name, labels, params, resultType, async, throws)
	return node, true, nil
}

func (p *parser) tryParseConstructorSpec(moduleName string, contextNames []string, base *Node) (*Node, bool, error) {
	if debugEnabled {
		debugf("tryParseConstructorSpec: entry at pos=%d remaining=%q\n", p.pos, string(p.data[p.pos:]))
	}
	state := p.saveState()
	_ = p.skipPrivateDeclName()
	labels, err := p.parseLabelList()
	if err != nil {
		p.restoreState(state)
		if debugEnabled {
			debugf("tryParseConstructorSpec: parseLabelList error, restoring to pos=%d\n", state.pos)
		}
		return nil, false, err
	}
	sigStart := p.pos
	params, resultType, async, throws, err := p.parseFunctionSignature()
	if err != nil {
		p.restoreState(state)
		return nil, false, fmt.Errorf("parse constructor signature: %w", err)
	}

	// IMPORTANT: Once parseFunctionSignature succeeds, we must NOT restore state even if
	// later checks fail. The signature parsing consumed input and may have pushed nodes/substitutions.
	// Convert subsequent failures to hard errors or just return ok=false WITHOUT restoring.

	if base != nil {
		resultType = base.Clone()
	}
	if len(labels) > 0 && len(params) < len(labels) {
		// This fallback path should also avoid restoring state after successful signature parse.
		// For now, if we need fallback, we have a problem - best to just fail cleanly.
		// Actually, the fallback reparses from sigStart, which might be OK since it's before
		// the signature. But to be safe, let's keep this path for now but note it's risky.
		p.restoreState(state)
		p.pos = sigStart
		fallbackParams, fallbackResult, fbAsync, fbThrows, fbErr := p.parseConstructorSignatureFallback(moduleName, contextNames)
		if fbErr != nil {
			p.restoreState(state)
			return nil, false, nil
		}
		params = fallbackParams
		resultType = fallbackResult
		async = fbAsync
		throws = fbThrows
	}
	if debugEnabled {
		debugf("constructor spec after signature pos=%d remaining=%q\n", p.pos, string(p.data[p.pos:]))
	}
	_ = p.parseFileDiscriminator()
	if !p.eof() && p.peek() == '_' {
		p.consume()
	}
	if !p.eof() && p.peek() == 't' {
		p.consume()
	}
	if !p.eof() && p.peek() == 'c' {
		p.consume()
	}
	// Don't restore state here - signature already parsed and consumed input
	if err := p.expect('f'); err != nil {
		// Not a constructor - return ok=false but DON'T restore state
		return nil, false, nil
	}
	if p.eof() {
		p.restoreState(state)
		return nil, false, fmt.Errorf("unterminated constructor suffix")
	}
	code := p.consume()
	var baseName string
	switch code {
	case 'C':
		baseName = "__allocating_init"
	case 'c':
		baseName = "init"
	default:
		p.restoreState(state)
		return nil, false, nil
	}
	if baseName == "__allocating_init" && resultType != nil && resultType.Kind != KindClass {
		baseName = "init"
	}
	if base != nil {
		resultType = base.Clone()
	}
	node := buildFunctionNode(moduleName, contextNames, baseName, labels, params, resultType, async, throws)
	return node, true, nil
}

func (p *parser) tryParseVariableSpec(moduleName string, contextNames []string) (*Node, bool, error) {
	state := p.saveState()
	name, err := p.readEntityName()
	if err != nil {
		p.restoreState(state)
		return nil, false, nil
	}
	if _, err := p.parseLabelList(); err != nil {
		p.restoreState(state)
		return nil, false, err
	}
	varType, err := p.parseType()
	if err != nil {
		p.restoreState(state)
		return nil, false, nil
	}
	if err := p.expect('v'); err != nil {
		p.restoreState(state)
		return nil, false, nil
	}
	if p.eof() {
		p.restoreState(state)
		return nil, false, fmt.Errorf("unterminated variable accessor")
	}
	qualName := buildQualifiedName(moduleName, contextNames, name)
	variable := NewNode(KindVariable, qualName)
	variable.Append(varType)

	code := []byte{p.consume()}
	switch code[0] {
	case 'a', 'l':
		if p.eof() {
			return nil, false, fmt.Errorf("unterminated accessor sequence after %q", code[0])
		}
		code = append(code, p.consume())
	}

	key := string(code)
	if key == "p" {
		return variable, true, nil
	}
	label, ok := accessorDisplay[key]
	if !ok {
		return nil, false, fmt.Errorf("unsupported accessor code %q", key)
	}
	accessor := NewNode(KindAccessor, label)
	accessor.Append(variable)
	return accessor, true, nil
}

func (p *parser) applySymbolSuffixes(node *Node) (*Node, error) {
	current := node
	for !p.eof() {
		switch p.peek() {
		case 'M':
			if p.pos+1 >= len(p.data) {
				return nil, fmt.Errorf("truncated metatype suffix")
			}
			suffix := p.data[p.pos+1]
			switch suffix {
			case 'a':
				p.pos += 2
				current = wrapDescriptorNode(KindTypeMetadataAccessFunction, current)
			case 'b':
				p.pos += 2
				current = wrapDescriptorNode(KindCanonicalSpecializedGenericTypeMetadataAccessFunction, current)
			case 'f':
				p.pos += 2
				current = wrapDescriptorNode(KindFullTypeMetadata, current)
			case 'i':
				p.pos += 2
				current = wrapDescriptorNode(KindTypeMetadataInstantiationFunction, current)
			case 'I':
				p.pos += 2
				current = wrapDescriptorNode(KindTypeMetadataInstantiationCache, current)
			case 'l':
				p.pos += 2
				current = wrapDescriptorNode(KindTypeMetadataSingletonInitializationCache, current)
			case 'p':
				p.pos += 2
				current = wrapDescriptorNode(KindProtocolDescriptor, current)
			case 'r':
				p.pos += 2
				current = wrapDescriptorNode(KindTypeMetadataCompletionFunction, current)
			case 'V':
				p.pos += 2
				current = wrapDescriptorNode(KindPropertyDescriptor, current)
			case 'n':
				p.pos += 2
				current = wrapDescriptorNode(KindNominalTypeDescriptor, current)
			case 'o':
				p.pos += 2
				current = wrapDescriptorNode(KindClassMetadataBaseOffset, current)
			case 's':
				p.pos += 2
				current = wrapDescriptorNode(KindObjCResilientClassStub, current)
			case 't':
				p.pos += 2
				current = wrapDescriptorNode(KindFullObjCResilientClassStub, current)
			case 'u':
				p.pos += 2
				current = wrapDescriptorNode(KindMethodLookupFunction, current)
			case 'U':
				p.pos += 2
				current = wrapDescriptorNode(KindObjCMetadataUpdateFunction, current)
			case 'z':
				p.pos += 2
				current = wrapDescriptorNode(KindCanonicalPrespecializedGenericTypeCachingOnceToken, current)
			default:
				return current, nil
			}
		case 'T':
			if p.pos+1 >= len(p.data) {
				return nil, fmt.Errorf("truncated thunk suffix")
			}
			suffix := p.data[p.pos+1]
			switch suffix {
			case 'q':
				p.pos += 2
				current = wrapDescriptorNode(KindMethodDescriptor, current)
			default:
				return current, nil
			}
		default:
			return current, nil
		}
	}
	return current, nil
}

func wrapDescriptorNode(kind NodeKind, child *Node) *Node {
	n := NewNode(kind, "")
	n.Append(child)
	return n
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

func (p *parser) parseLabelList() ([]string, error) {
	if debugEnabled {
		debugf("parseLabelList: entry at pos=%d remaining=%q\n", p.pos, string(p.data[p.pos:]))
	}
	labels := []string{}
	for !p.eof() {
		switch {
		case p.peek() == '_':
			p.consume()
			labels = append(labels, "_")
			if debugEnabled {
				debugf("parseLabelList: parsed underscore label, pos now %d\n", p.pos)
			}
		case isDigit(p.peek()):
			label, err := p.readIdentifierNoSubst()
			if err != nil {
				if debugEnabled {
					debugf("parseLabelList: readIdentifierNoSubst failed: %v\n", err)
				}
				return nil, err
			}
			labels = append(labels, label)
			if debugEnabled {
				debugf("parseLabelList: parsed label %q, pos now %d\n", label, p.pos)
			}
		default:
			if len(labels) == 0 {
				if debugEnabled {
					debugf("parseLabelList: no labels found, returning nil at pos=%d\n", p.pos)
				}
				return nil, nil
			}
			if debugEnabled {
				debugf("parseLabelList: done, returning %d labels at pos=%d\n", len(labels), p.pos)
			}
			return labels, nil
		}
	}
	if len(labels) == 0 {
		if debugEnabled {
			debugf("parseLabelList: EOF with no labels\n")
		}
		return nil, nil
	}
	if debugEnabled {
		debugf("parseLabelList: EOF with %d labels\n", len(labels))
	}
	return labels, nil
}

func (p *parser) parseConstructorSignatureFallback(moduleName string, contextNames []string) ([]*Node, *Node, bool, bool, error) {
	params := []*Node{}
loop:
	for {
		if p.eof() {
			return nil, nil, false, false, fmt.Errorf("unterminated constructor parameters")
		}
		param, err := p.parseType()
		if err != nil {
			return nil, nil, false, false, err
		}
		params = append(params, param)
		if p.eof() {
			return nil, nil, false, false, fmt.Errorf("unterminated constructor tuple suffix")
		}
		switch p.peek() {
		case '_':
			p.consume()
			if p.eof() {
				return nil, nil, false, false, fmt.Errorf("unterminated constructor tuple suffix")
			}
			if p.peek() == 't' {
				p.consume()
				break loop
			}
		case 't':
			p.consume()
			break loop
		default:
			return nil, nil, false, false, fmt.Errorf("unexpected constructor tuple separator %q", p.peek())
		}
	}
	if len(contextNames) == 0 {
		return params, NewNode(KindUnknown, ""), false, false, nil
	}
	names := append([]string{moduleName}, contextNames...)
	resultType := buildNominal(KindClass, names)
	return params, resultType, false, false, nil
}

func (p *parser) parseFunctionSignature() ([]*Node, *Node, bool, bool, error) {
	if debugEnabled {
		debugf("parseFunctionSignature: start pos=%d remaining=%q\n", p.pos, string(p.data[p.pos:]))
	}
	resultType, err := p.parseType()
	if err != nil {
		if debugEnabled {
			debugf("parseFunctionSignature: parseType error at pos=%d: %v\n", p.pos, err)
		}
		return nil, nil, false, false, err
	}
	if debugEnabled {
		debugf("parseFunctionSignature: parsed result kind=%v text=%s pos=%d\n", resultType.Kind, resultType.Text, p.pos)
	}
	if len(p.pending) > 0 {
		p.pending = p.pending[:0]
	}
	state := p.saveState()
	paramsTuple := NewNode(KindTuple, "")
	async := false
	throws := false

	if debugEnabled {
		debugf("parseFunctionSignature: result=%s pos=%d remaining=%q\n", func() string {
			if resultType != nil {
				return Format(resultType)
			}
			return "<nil>"
		}(), p.pos, string(p.data[p.pos:]))
	}

	if resultType.Kind == KindFunction && len(resultType.Children) >= 2 {
		fn := resultType
		paramsTuple = fn.Children[0]
		resultType = fn.Children[1]
		async = fn.Flags.Async
		throws = fn.Flags.Throws
	} else {
		if tuple, ok, err := p.parseFunctionInput(); err != nil {
			return nil, nil, false, false, err
		} else if ok {
			if debugEnabled {
				debugf("parseFunctionSignature: got params tuple kind=%v with %d elems\n", tuple.Kind, len(tuple.Children))
			}
			paramsTuple = tuple
		} else {
			if debugEnabled {
				debugf("parseFunctionSignature: parseFunctionInput failed, restoring to %d\n", state.pos)
			}
			p.restoreState(state)
		}

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

	return paramNodes, resultType, async, throws, nil
}

func buildFunctionNode(moduleName string, contextNames []string, baseName string, labels []string, params []*Node, result *Node, async, throws bool) *Node {
	normalized := normalizeArgumentLabels(len(params), labels)
	argumentTuple := NewNode(KindArgumentTuple, "")
	for idx, param := range params {
		label := "_"
		if normalized != nil && idx < len(normalized) && normalized[idx] != "" {
			label = normalized[idx]
		}
		arg := NewNode(KindArgument, label)
		arg.Append(param)
		argumentTuple.Append(arg)
	}
	funcNode := NewNode(KindFunction, buildQualifiedName(moduleName, contextNames, baseName))
	funcNode.Flags.Async = async
	funcNode.Flags.Throws = throws
	funcNode.Append(argumentTuple, result)
	return funcNode
}

func (p *parser) parseFileDiscriminator() bool {
	save := p.pos
	if !isDigit(p.peek()) {
		return false
	}
	ident, err := p.readIdentifier()
	if err != nil || ident == "" {
		p.pos = save
		return false
	}
	if !p.matchString("Ll") {
		p.pos = save
		return false
	}
	return true
}
func (p *parser) readEntityName() (string, error) {
	save := p.pos
	if debugEnabled {
		debugf("readEntityName: entry at pos=%d remaining=%q\n", p.pos, string(p.data[p.pos:]))
	}
	if !p.eof() && (p.peek() == 'C' || p.peek() == 'c') {
		prefix := p.consume()
		if !p.eof() && isDigit(p.peek()) {
			length, err := p.readNumber()
			if err == nil && length > 0 && p.pos+length <= len(p.data) {
				start := p.pos
				p.pos += length
				name := string(p.data[start:p.pos])
				if debugEnabled {
					debugf("readEntityName: parsed private name %q, pos now %d\n", name, p.pos)
				}
				return name, nil
			}
		}
		p.pos = save
		_ = prefix
	}
	name, err := p.readIdentifier()
	if debugEnabled {
		if err != nil {
			debugf("readEntityName: readIdentifier failed: %v\n", err)
		} else {
			debugf("readEntityName: parsed identifier %q, pos now %d\n", name, p.pos)
		}
	}
	return name, err
}

func (p *parser) skipPrivateDeclName() bool {
	save := p.pos
	if p.eof() || (p.peek() != 'C' && p.peek() != 'c') {
		return false
	}
	p.consume()
	if !p.eof() && isDigit(p.peek()) {
		length, err := p.readNumber()
		if err == nil && length > 0 && p.pos+length <= len(p.data) {
			p.pos += length
			return true
		}
	}
	p.pos = save
	return false
}
