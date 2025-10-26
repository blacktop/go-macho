package swiftdemangle

import (
	"fmt"
	"os"
)

var debugEnabled = os.Getenv("GO_MACHO_SWIFT_DEBUG") != ""

func debugf(format string, args ...interface{}) {
	if debugEnabled {
		fmt.Printf(format, args...)
	}
}
