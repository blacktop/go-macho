package macho

import (
	"fmt"
	"os"
	"testing"
)

func TestNewFatFile(t *testing.T) {

	f, err := os.Open("/usr/lib/libcompression.dylib")
	if err != nil {
		t.Fatal(err)
	}

	fat, err := NewFatFile(f)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(fat.Arches[0].FileTOC.String())

	if fat.Arches[0].UUID().ID != "test" {
		t.Errorf("macho.UUID() = %s; want test", fat.Arches[0].UUID())
	}
}
