package macho

import (
	"os"
	"testing"
)

func TestNewFile(t *testing.T) {
	f, err := os.Open("/usr/lib/libcompression.dylib")
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if m.UUID().ID != "test" {
		t.Errorf("macho.UUID() = %s; want test", m.UUID())
	}
}
