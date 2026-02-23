package macho

import (
	"errors"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types/swift"
)

func fullSwiftTypeName(typ *swift.Type) string {
	var parts []string
	for t := typ; t != nil; t = t.Parent {
		if t.Name != "" {
			parts = append([]string{t.Name}, parts...)
		}
	}
	return strings.Join(parts, ".")
}

func matchSwiftFieldType(name string, fieldMap map[string]string) (string, bool) {
	if fieldMap == nil {
		return "", false
	}
	if typ, ok := fieldMap[name]; ok {
		return typ, true
	}
	trimmed := strings.TrimPrefix(name, "_")
	if typ, ok := fieldMap[trimmed]; ok {
		return typ, true
	}
	return "", false
}

func swiftClassLookupNames(fullName string, normalize func(string) string) map[string]struct{} {
	names := make(map[string]struct{}, 6)
	addName := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		names[name] = struct{}{}
	}
	addLegacyDemangled := func(name string) {
		if demangled, ok := legacySwiftObjCClassName(name); ok {
			addName(demangled)
		}
	}

	addName(fullName)
	trimmedObjCPrefix := strings.TrimPrefix(fullName, "_OBJC_CLASS_$_")
	addName(trimmedObjCPrefix)
	if strings.HasPrefix(trimmedObjCPrefix, "Tt") {
		addName("_" + trimmedObjCPrefix)
	}
	if strings.HasPrefix(trimmedObjCPrefix, "_Tt") {
		addName(strings.TrimPrefix(trimmedObjCPrefix, "_"))
	}

	addLegacyDemangled(fullName)
	if trimmedObjCPrefix != fullName {
		addLegacyDemangled(trimmedObjCPrefix)
	}

	if normalize != nil {
		seeds := make([]string, 0, len(names))
		for name := range names {
			seeds = append(seeds, name)
		}
		for _, name := range seeds {
			addName(normalize(name))
		}
	}

	return names
}

func swiftClassTypeMatches(typeName string, lookupNames map[string]struct{}, normalize func(string) string) bool {
	typeName = strings.TrimSpace(typeName)
	if typeName == "" {
		return false
	}
	if _, ok := lookupNames[typeName]; ok {
		return true
	}
	if normalize != nil {
		if _, ok := lookupNames[normalize(typeName)]; ok {
			return true
		}
	}
	return false
}

func legacySwiftObjCClassName(fullName string) (string, bool) {
	name := strings.TrimSpace(fullName)
	name = strings.TrimPrefix(name, "_")
	if !strings.HasPrefix(name, "Tt") {
		return "", false
	}

	encoded := trimLegacySwiftContextKindPrefixes(name[len("Tt"):])
	if len(encoded) == 0 {
		return "", false
	}

	parts := make([]string, 0, 4)
	for len(encoded) > 0 {
		partLen, digits := consumeDecimalPrefix(encoded)
		if digits == 0 || partLen <= 0 {
			return "", false
		}
		if digits+partLen > len(encoded) {
			return "", false
		}
		part := encoded[digits : digits+partLen]
		if part == "" {
			return "", false
		}
		parts = append(parts, part)
		encoded = encoded[digits+partLen:]
	}

	if len(parts) < 2 {
		return "", false
	}

	return strings.Join(parts, "."), true
}

func trimLegacySwiftContextKindPrefixes(encoded string) string {
	for len(encoded) > 0 {
		switch encoded[0] {
		case 'C', 'V', 'O', 'P':
			encoded = encoded[1:]
		default:
			return encoded
		}
	}
	return encoded
}

func consumeDecimalPrefix(input string) (value int, digits int) {
	for digits < len(input) {
		ch := input[digits]
		if ch < '0' || ch > '9' {
			break
		}
		value = value*10 + int(ch-'0')
		digits++
	}
	return value, digits
}

func (f *File) swiftFieldTypesForClass(fullName string) (map[string]string, error) {
	types, err := f.GetSwiftTypes()
	if err != nil {
		return nil, err
	}

	lookupNames := swiftClassLookupNames(fullName, f.normalizeSwiftIdentifier)

	for i := range types {
		typ := &types[i]
		if typ.Kind != swift.CDKindClass {
			continue
		}
		if !swiftClassTypeMatches(fullSwiftTypeName(typ), lookupNames, f.normalizeSwiftIdentifier) {
			continue
		}
		if typ.Fields == nil {
			return nil, nil
		}
		fieldMap := make(map[string]string)
		for _, rec := range typ.Fields.Records {
			if rec.Name == "" || rec.MangledType == "" {
				continue
			}
			fieldMap[rec.Name] = rec.MangledType
		}
		return fieldMap, nil
	}

	return nil, nil
}

func (f *File) swiftASCIITypeGuess(addr uint64) (string, bool) {
	buf := make([]byte, 0x400)
	n, err := f.ReadAtAddr(buf, addr)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false
	}
	buf = buf[:n]

	best := ""
	bestScore := -1
	for i := 0; i < len(buf); {
		for i < len(buf) && buf[i] == 0 {
			i++
		}
		if i >= len(buf) {
			break
		}
		j := i
		for j < len(buf) && buf[j] != 0 {
			j++
		}
		candidate := string(buf[i:j])
		score := swiftAsciiScore(candidate)
		if score > bestScore {
			bestScore = score
			best = candidate
		}
		i = j + 1
	}
	if bestScore > 0 {
		return best, true
	}
	return "", false
}
