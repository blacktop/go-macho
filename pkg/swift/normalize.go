package swift

import (
	"strings"
)

var methodPrefixes = []string{"func ", "method ", "getter ", "setter ", "modify ", "init "}

// NormalizeIdentifier attempts to demangle the provided identifier and returns the best-effort human readable string.
func NormalizeIdentifier(name string) string {
	if demangled, ok := TryNormalizeIdentifier(name); ok {
		return demangled
	}
	return name
}

// TryNormalizeIdentifier returns the demangled identifier and a boolean indicating success.
func TryNormalizeIdentifier(name string) (string, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return name, false
	}

	for _, prefix := range methodPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			body := strings.TrimSpace(trimmed[len(prefix):])
			if demangled, ok := tryDemangleCandidate(body); ok {
				return prefix + demangled, true
			}
		}
	}

	return tryDemangleCandidate(trimmed)
}

func tryDemangleCandidate(candidate string) (string, bool) {
	if candidate == "" {
		return candidate, false
	}

	attempts := []string{candidate}
	if strings.HasPrefix(candidate, "_") {
		attempts = append(attempts, strings.TrimPrefix(candidate, "_"))
	}

	for _, attempt := range attempts {
		out, err := Demangle(attempt)
		if err != nil || out == "" {
			continue
		}
		return out, true
	}

	return candidate, false
}
