package swift

import (
	"fmt"

	swiftdemangle "github.com/blacktop/go-macho/internal/swiftdemangle"
)

type pureGoEngine struct{}

func newPureGoEngine() engine {
	return pureGoEngine{}
}

func (pureGoEngine) Demangle(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty input")
	}
	text, _, err := swiftdemangle.Demangle(input)
	return text, err
}

func (e pureGoEngine) DemangleSimple(input string) (string, error) {
	// TODO: provide a "simplified" formatter that mirrors swift-demangle -simplified.
	return e.Demangle(input)
}
