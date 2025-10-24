package demangle

import (
	"strconv"
	"strings"

	swiftdemangle "github.com/blacktop/go-macho/internal/swiftdemangle"
)

var methodPrefixes = []string{"func ", "method ", "getter ", "setter ", "modify ", "init "}

// NormalizeIdentifier returns a best-effort demangled representation of the input string.
func NormalizeIdentifier(name string) string {
	if demangled, ok := TryNormalizeIdentifier(name); ok {
		return demangled
	}
	return name
}

// TryNormalizeIdentifier attempts to demangle the provided identifier, returning the demangled form and a success flag.
func TryNormalizeIdentifier(name string) (string, bool) {
	for _, pref := range methodPrefixes {
		if strings.HasPrefix(name, pref) {
			body := strings.TrimSpace(name[len(pref):])
			if sym, ok := demangleSymbolName(body); ok {
				return pref + sym, true
			}
			if demangled, ok := demangleCandidateString(body); ok {
				return pref + demangled, true
			}
		}
	}

	if demangled, ok := demangleCandidateString(name); ok {
		return demangled, true
	}
	return name, false
}

func demangleCandidateString(candidate string) (string, bool) {
	trimmed := strings.TrimSpace(candidate)
	if trimmed == "" {
		return "", false
	}

	mangled := strings.TrimPrefix(trimmed, "_")
	clean := mangled
	for {
		if strings.HasPrefix(clean, "$s") || strings.HasPrefix(clean, "$S") {
			clean = clean[2:]
			continue
		}
		break
	}

	attempts := []string{}
	if clean != "" {
		attempts = append(attempts, clean)
	}
	if clean != mangled && mangled != "" {
		attempts = append(attempts, mangled)
	}

	for _, attempt := range attempts {
		node, err := swiftdemangle.New(nil).DemangleType([]byte(attempt))
		if err != nil {
			continue
		}
		if formatted := swiftdemangle.Format(node); formatted != "" {
			return formatted, true
		}
	}

	if tuple, ok := demangleTupleFallback(clean); ok {
		return tuple, true
	}

	if stable, ok := demangleStableSymbolName(mangled); ok {
		return stable, true
	}

	if legacy, ok := demangleLegacyTypeName(trimmed); ok {
		return legacy, true
	}

	if symbol, ok := demangleSymbolName(trimmed); ok {
		return symbol, true
	}

	if tuple, ok := demangleTupleFallback(trimmed); ok {
		return tuple, true
	}

	if strings.Contains(trimmed, ".") {
		return trimmed, true
	}

	return trimmed, true
}

func demangleTupleFallback(raw string) (string, bool) {
	if raw == "" || !strings.Contains(raw, "_") {
		return "", false
	}
	if strings.ContainsAny(raw, "$ ") {
		return "", false
	}

	base, suffix := trimOptionalSuffix(raw)
	if strings.HasPrefix(base, "_") || strings.HasSuffix(base, "_") {
		return "", false
	}

	parts := strings.Split(base, "_")
	if len(parts) < 2 {
		return "", false
	}

	elements := make([]string, len(parts))
	for idx, part := range parts {
		if part == "" {
			return "", false
		}
		fragment := part
		if idx == len(parts)-1 && strings.HasSuffix(fragment, "t") {
			fragment = fragment[:len(fragment)-1]
			if fragment == "" {
				return "", false
			}
		}
		elem, ok := demangleTypeFragment(fragment)
		if !ok {
			return "", false
		}
		elements[idx] = elem
	}

	result := "(" + strings.Join(elements, ", ") + ")"
	if suffix != "" {
		result += suffix
	}
	return result, true
}

func trimOptionalSuffix(raw string) (string, string) {
	base := raw
	var suffix strings.Builder
	for len(base) > 2 && strings.HasSuffix(base, "Sg") {
		base = base[:len(base)-2]
		suffix.WriteString("?")
	}
	return base, suffix.String()
}

func demangleTypeFragment(fragment string) (string, bool) {
	if fragment == "" {
		return "", false
	}

	if node, err := swiftdemangle.New(nil).DemangleType([]byte(fragment)); err == nil {
		if formatted := swiftdemangle.Format(node); formatted != "" {
			return formatted, true
		}
	}

	if mapped, ok := swiftStandardTypes[fragment]; ok {
		return mapped, true
	}

	return "", false
}

func demangleLegacyTypeName(mangled string) (string, bool) {
	if !strings.HasPrefix(mangled, "_T") {
		return "", false
	}

	rest := mangled[2:]
	if len(rest) == 0 {
		return "", false
	}
	if rest[0] == 't' {
		rest = rest[1:]
		if len(rest) == 0 {
			return "", false
		}
	}

	if rest[0] >= 'A' && rest[0] <= 'Z' || rest[0] >= 'a' && rest[0] <= 'z' {
		rest = rest[1:]
	}

	var parts []string
	for len(rest) > 0 {
		idx := 0
		for idx < len(rest) && rest[idx] >= '0' && rest[idx] <= '9' {
			idx++
		}
		if idx == 0 {
			break
		}
		length, err := strconv.Atoi(rest[:idx])
		if err != nil || length < 0 {
			return "", false
		}
		rest = rest[idx:]
		if length > len(rest) {
			return "", false
		}
		segment := rest[:length]
		rest = rest[length:]
		if segment != "" {
			parts = append(parts, segment)
		}
	}

	if len(parts) == 0 {
		return "", false
	}

	return strings.Join(parts, "."), true
}

func demangleStableSymbolName(symbol string) (string, bool) {
	if len(symbol) == 0 {
		return "", false
	}

	switch {
	case strings.HasPrefix(symbol, "$s"), strings.HasPrefix(symbol, "$S"):
		symbol = symbol[2:]
	default:
		return "", false
	}

	if strings.HasSuffix(symbol, "Sg") {
		baseSymbol := "$s" + symbol[:len(symbol)-2]
		baseDemangled := NormalizeIdentifier(baseSymbol)
		if baseDemangled != baseSymbol {
			return baseDemangled + "?", true
		}
	}

	if len(symbol) == 2 && symbol[0] == 'S' {
		if text, ok := swiftStandardTypes[string(symbol[1])]; ok {
			return text, true
		}
	}

	var parts []string
	suffix := ""
	for len(symbol) > 0 {
		switch symbol[0] {
		case 's':
			parts = append(parts, "Swift")
			symbol = symbol[1:]
			continue
		case 'S':
			symbol = symbol[1:]
			continue
		case 'o':
			symbol = symbol[1:]
			continue
		}

		if symbol[0] < '0' || symbol[0] > '9' {
			suffix = symbol
			symbol = ""
			break
		}

		idx := 1
		for idx < len(symbol) && symbol[idx] >= '0' && symbol[idx] <= '9' {
			idx++
		}
		length, err := strconv.Atoi(symbol[:idx])
		if err != nil || length < 0 {
			return "", false
		}
		symbol = symbol[idx:]
		if length > len(symbol) {
			return "", false
		}
		segment := symbol[:length]
		symbol = symbol[length:]
		if segment != "" {
			parts = append(parts, segment)
		}
	}

	if len(parts) == 0 {
		return "", false
	}

	if suffix != "" {
		if suffix == "Sg" && len(parts) > 0 {
			last := parts[len(parts)-1]
			parts[len(parts)-1] = last + "?"
		}
	}

	return strings.Join(parts, "."), true
}

func demangleSymbolName(symbol string) (string, bool) {
	s := strings.TrimPrefix(symbol, "_")
	if !strings.HasPrefix(s, "$s") && !strings.HasPrefix(s, "$S") {
		return "", false
	}
	s = s[2:]
	pos := 0

	readIdent := func() (string, bool) {
		if pos >= len(s) || s[pos] < '0' || s[pos] > '9' {
			return "", false
		}
		start := pos
		for pos < len(s) && s[pos] >= '0' && s[pos] <= '9' {
			pos++
		}
		length, err := strconv.Atoi(s[start:pos])
		if err != nil || pos+length > len(s) {
			return "", false
		}
		ident := s[pos : pos+length]
		pos += length
		return ident, true
	}

	module, ok := readIdent()
	if !ok {
		return "", false
	}
	contexts := []string{}

	for pos < len(s) {
		ident, ok := readIdent()
		if !ok {
			break
		}
		if pos >= len(s) {
			break
		}
		kind := s[pos]
		if isContextKind(kind) {
			pos++
			contexts = append(contexts, ident)
			continue
		}
		baseParts := []string{ident}
		for pos < len(s) {
			if s[pos] == '_' {
				pos++
				ident, ok := readIdent()
				if !ok {
					break
				}
				baseParts = append(baseParts, ident)
				continue
			}
			break
		}
		name := baseParts[0]
		if len(baseParts) > 1 {
			labels := make([]string, len(baseParts)-1)
			for i, label := range baseParts[1:] {
				if label == "" {
					labels[i] = "_"
				} else {
					labels[i] = label + ":"
				}
			}
			name += "(" + strings.Join(labels, " ") + ")"
		}
		parts := append([]string{module}, contexts...)
		parts = append(parts, name)
		return strings.Join(parts, "."), true
	}

	return module, true
}

func isContextKind(b byte) bool {
	switch b {
	case 'C', 'V', 'O', 'E', 'P', 'B', 'I', 'N', 'T', 'A', 'M', 'G':
		return true
	default:
		return false
	}
}

var swiftStandardTypes = map[string]string{
	"A": "Swift.AutoreleasingUnsafeMutablePointer",
	"B": "Swift.BinaryFloatingPoint",
	"D": "Swift.Dictionary",
	"E": "Swift.Encodable",
	"F": "Swift.FloatingPoint",
	"G": "Swift.RandomNumberGenerator",
	"H": "Swift.Hashable",
	"I": "Swift.DefaultIndices",
	"J": "Swift.Character",
	"K": "Swift.BidirectionalCollection",
	"L": "Swift.Comparable",
	"M": "Swift.MutableCollection",
	"N": "Swift.ClosedRange",
	"O": "Swift.ObjectIdentifier",
	"P": "Swift.UnsafePointer",
	"Q": "Swift.Equatable",
	"R": "Swift.UnsafeBufferPointer",
	"S": "Swift.String",
	"T": "Swift.Sequence",
	"U": "Swift.UnsignedInteger",
	"V": "Swift.UnsafeRawPointer",
	"W": "Swift.UnsafeRawBufferPointer",
	"X": "Swift.RangeExpression",
	"Y": "Swift.RawRepresentable",
	"Z": "Swift.SignedInteger",
	"a": "Swift.Array",
	"b": "Swift.Bool",
	"d": "Swift.Double",
	"e": "Swift.Decodable",
	"f": "Swift.Float",
	"h": "Swift.Set",
	"i": "Swift.Int",
	"j": "Swift.Numeric",
	"k": "Swift.RandomAccessCollection",
	"l": "Swift.Collection",
	"m": "Swift.RangeReplaceableCollection",
	"n": "Swift.Range",
	"p": "Swift.UnsafeMutablePointer",
	"q": "Swift.Optional",
	"r": "Swift.UnsafeMutableBufferPointer",
	"s": "Swift.Substring",
	"t": "Swift.IteratorProtocol",
	"u": "Swift.UInt",
	"v": "Swift.UnsafeMutableRawPointer",
	"w": "Swift.UnsafeMutableRawBufferPointer",
	"x": "Swift.Strideable",
	"y": "Swift.StringProtocol",
	"z": "Swift.BinaryInteger",
}
