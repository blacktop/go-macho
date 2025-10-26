package swift

import "regexp"

var blobTokenPattern = regexp.MustCompile(`(?:_?\$[sS]|S[oO])[A-Za-z0-9_]+`)

// Demangle returns the fully formatted Swift symbol text.
func Demangle(input string) (string, error) {
	return defaultEngine.Demangle(input)
}

// DemangleSimple returns a simplified Swift symbol name matching swift-demangle -simplified when available.
func DemangleSimple(input string) (string, error) {
	return defaultEngine.DemangleSimple(input)
}

// DemangleBlob replaces every mangled token in blob with its demangled equivalent.
func DemangleBlob(blob string) string {
	return blobTokenPattern.ReplaceAllStringFunc(blob, func(token string) string {
		out, err := Demangle(token)
		if err != nil {
			return token
		}
		return out
	})
}

// DemangleSimpleBlob replaces mangled tokens with simplified demangled text.
func DemangleSimpleBlob(blob string) string {
	return blobTokenPattern.ReplaceAllStringFunc(blob, func(token string) string {
		out, err := DemangleSimple(token)
		if err != nil {
			return token
		}
		return out
	})
}
