package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/blacktop/go-macho/pkg/swift"
)

func main() {
	cmd := flag.String("cmd", "go run ./cmd/ipsw macho info /tmp/043-72754-034.dmg.mount/System/Library/PrivateFrameworks/LockdownMode.framework/lockdownmoded --swift --swift-all --demangle --no-color", "command to run for collecting Swift symbols")
	cwd := flag.String("cwd", ".", "working directory where the command should run")
	emitGo := flag.Bool("emit-go", true, "print Go test case entries for unsupported symbols")
	flag.Parse()

	fmt.Printf("Running darwin demangler command in %s\n", *cwd)
	output, err := runCommand(*cmd, *cwd, map[string]string{
		"CGO_ENABLED": "1",
		"NO_COLOR":    "1",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "command failed: %v\n", err)
		fmt.Fprint(os.Stderr, output)
		os.Exit(1)
	}

	symbols := extractSymbols(output)
	fmt.Printf("Found %d symbols in darwin output\n", len(symbols))

	unsupported := make([]string, 0)
	for _, sym := range symbols {
		if !isInteresting(sym) {
			continue
		}
		if _, derr := swift.Demangle(sym); derr != nil {
			unsupported = append(unsupported, sym)
		}
	}

	fmt.Printf("Unsupported symbols (%d):\n", len(unsupported))
	for _, sym := range unsupported {
		fmt.Println("  ", sym)
	}

	if *emitGo {
		fmt.Println("\nGo test cases:")
		for _, sym := range unsupported {
			fmt.Printf("        {\"%s\", false},\n", sym)
		}
	}
}

func runCommand(command, cwd string, extraEnv map[string]string) (string, error) {
	cmd := exec.Command("bash", "-lc", command)
	cmd.Dir = cwd
	env := os.Environ()
	for k, v := range extraEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func extractSymbols(output string) []string {
	seen := make(map[string]bool)
	var result []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "DEMANGLING:") {
			continue
		}
		sym := strings.TrimSpace(strings.TrimPrefix(line, "DEMANGLING:"))
		if sym == "" {
			continue
		}
		if !seen[sym] {
			seen[sym] = true
			result = append(result, sym)
		}
	}
	return result
}

func isInteresting(sym string) bool {
	if strings.HasPrefix(sym, "_$") || strings.HasPrefix(sym, "$s") {
		return true
	}
	return false
}
