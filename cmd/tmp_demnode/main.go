package main

import (
	"fmt"

	swiftdemangle "github.com/blacktop/go-macho/internal/swiftdemangle"
)

type mockResolver struct{}

func (mockResolver) ResolveType(control byte, payload []byte, refIndex int) (*swiftdemangle.Node, error) {
	return swiftdemangle.NewNode(swiftdemangle.KindIdentifier, fmt.Sprintf("<mock:%02x>", control)), nil
}

func main() {
	samples := []string{
		"SiIegg_",
		"_pSgIegg_",
		"_$sSgIegg_",
		"Sb\x02\x00\x00\x00\x00_pSgIegyg_",
		"ytIeAgHr_",
		"_$ss12CaseIterableP8AllCasesAB_SlTn",
	}
	for _, s := range samples {
		text, _, err := swiftdemangle.DemangleTypeString(s, swiftdemangle.WithResolver(mockResolver{}))
		fmt.Printf("%q -> %q err=%v\n", s, text, err)
	}
}
