package main

import (
    "fmt"

    sd "github.com/blacktop/go-macho/internal/swiftdemangle"
)

func main() {
    tests := []string{"_$sSgIegg_", "_$sSgIegyg_", "_$sSo7NSErrorCSgIeyBy_"}
    for _, t := range tests {
        out, _, err := sd.Demangle(t)
        fmt.Printf("%s => err=%v out=%q\n", t, err, out)
    }
}
