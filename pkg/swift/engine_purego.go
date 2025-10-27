package swift

import (
	"fmt"
	"log"
	"os"
	"strings"

	swiftdemangle "github.com/blacktop/go-macho/internal/swiftdemangle"
)

var traceSymbols = os.Getenv("GO_MACHO_SWIFT_TRACE") != ""
var logInputs = os.Getenv(debugEnvVar) != ""

type pureGoEngine struct{}

func newPureGoEngine() engine {
	return pureGoEngine{}
}

func (pureGoEngine) Demangle(input string) (string, error) {
	if logInputs {
		log.Printf("purego demangle input: %s", input)
	}
	if input == "" {
		return "", fmt.Errorf("empty input")
	}
	if !looksLikeSwiftSymbol(input) {
		return input, nil
	}
	if traceSymbols {
		log.Printf("purego demangle start: %s", input)
	}
	text, _, err := swiftdemangle.Demangle(input)
	if traceSymbols {
		if err != nil {
			log.Printf("purego demangle error: %v", err)
		} else {
			log.Printf("purego demangle ok: %s", text)
		}
	}
	return text, err
}

func (e pureGoEngine) DemangleSimple(input string) (string, error) {
	// TODO: provide a "simplified" formatter that mirrors swift-demangle -simplified.
	return e.Demangle(input)
}

func (pureGoEngine) DemangleType(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty input")
	}
	if traceSymbols {
		log.Printf("purego demangle type start: %s", input)
	}
	// Use DemangleTypeString for type-specific demangling
	text, _, err := swiftdemangle.DemangleTypeString(input)
	if traceSymbols {
		if err != nil {
			log.Printf("purego demangle type error: %v", err)
		} else {
			log.Printf("purego demangle type ok: %s", text)
		}
	}
	return text, err
}

func looksLikeSwiftSymbol(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	symbolPrefixes := []string{"$s", "$S", "_$s", "_$S", "_T", "__T"}
	for _, prefix := range symbolPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	if strings.Contains(trimmed, "_$s") || strings.Contains(trimmed, "$s.") {
		return true
	}
	if strings.HasPrefix(trimmed, "So") && strings.HasSuffix(trimmed, "C") {
		return true
	}
	return false
}
