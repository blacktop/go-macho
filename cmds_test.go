package macho

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestThreadLoadSize(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, command := range []types.LoadCmd{types.LC_THREAD, types.LC_UNIXTHREAD} {
			for _, states := range [][]types.ThreadState{
				nil,
				{{Flavor: 1, Count: 2, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
				{{Flavor: 1, Count: 2, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}, {Flavor: 2, Count: 2, Data: []byte{8, 7, 6, 5, 4, 3, 2, 1}}},
			} {
				thread := Thread{ThreadCmd: types.ThreadCmd{LoadCmd: command}, Threads: states}
				// LoadSize describes the current payload, including a constructed or edited
				// command whose stored Len and raw bytes have not yet been updated.
				var encoded bytes.Buffer
				if err := thread.Write(&encoded, order); err != nil {
					t.Fatal(err)
				}
				want := uint32(encoded.Len())
				if got := thread.LoadSize(); got != want {
					t.Fatalf("%v %s states=%d: size=%d written=%d", order, command, len(states), got, want)
				}
				thread.Len = want
				encoded.Reset()
				if err := thread.Write(&encoded, order); err != nil {
					t.Fatal(err)
				}
				header := make([]byte, 32)
				for i, value := range []uint32{uint32(types.Magic64), uint32(types.CPUArm64), 0, uint32(types.MH_EXECUTE), 1, want, 0, 0} {
					order.PutUint32(header[i*4:], value)
				}
				f, err := NewFile(bytes.NewReader(append(header, encoded.Bytes()...)))
				if err != nil {
					t.Fatal(err)
				}
				if got := f.Loads[0].LoadSize(); got != want {
					t.Fatalf("parsed %s size=%d want=%d", command, got, want)
				}
				if got := f.FileTOC.LoadSize(); got != want {
					t.Fatalf("TOC size=%d want=%d", got, want)
				}
				_ = f.Close()
			}
		}
	}
}
