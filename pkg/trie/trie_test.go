package trie

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// trieNode is a node of a synthetic export trie: an optional regular export
// at address and edges to children, in serialization order.
type trieNode struct {
	exported bool
	address  uint64
	edges    []trieEdge
}

type trieEdge struct {
	label string
	child *trieNode
}

// wantNode is a terminal node's name and the offset of its export payload.
type wantNode struct {
	name   string
	offset uint64
}

// encodeTrie lays the nodes out in pre-order and returns the trie bytes plus
// the terminal nodes in pre-order, the order ParseTrie must report them.
// Child offsets are one-byte ULEB128s.
func encodeTrie(t *testing.T, root *trieNode) ([]byte, []wantNode) {
	t.Helper()
	data, want := encodeTrieOffsets(root, 1)
	if data == nil {
		t.Fatal("synthetic trie needs multi-byte child offsets")
	}
	return data, want
}

// encodeTrieOffsets encodes child offsets as width-byte ULEB128s (1 or 4,
// padded with continuation bits). It returns nil if an offset doesn't fit.
func encodeTrieOffsets(root *trieNode, width int) ([]byte, []wantNode) {
	payload := func(n *trieNode) []byte {
		if !n.exported {
			return nil
		}
		return binary.AppendUvarint([]byte{0}, n.address) // regular flags, address
	}
	var order []*trieNode
	var names []string
	var walk func(n *trieNode, name string)
	walk = func(n *trieNode, name string) {
		order = append(order, n)
		names = append(names, name)
		for _, e := range n.edges {
			walk(e.child, name+e.label)
		}
	}
	walk(root, "")

	offsets := map[*trieNode]int{}
	next := 0
	for _, n := range order {
		offsets[n] = next
		p := payload(n)
		next += len(binary.AppendUvarint(nil, uint64(len(p)))) + len(p) + 1
		for _, e := range n.edges {
			next += len(e.label) + 1 + width // NUL + child offset
		}
	}
	if next >= 1<<(7*width) {
		return nil, nil
	}

	var data []byte
	var want []wantNode
	for i, n := range order {
		p := payload(n)
		data = binary.AppendUvarint(data, uint64(len(p)))
		if n.exported {
			want = append(want, wantNode{names[i], uint64(len(data))})
		}
		data = append(data, p...)
		data = append(data, byte(len(n.edges)))
		for _, e := range n.edges {
			data = append(data, e.label...)
			data = append(data, 0)
			off := offsets[e.child]
			for b := 0; b < width; b++ {
				v := byte(off>>(7*b)) & 0x7f
				if b < width-1 {
					v |= 0x80
				}
				data = append(data, v)
			}
		}
	}
	return data, want
}

func exportAt(addr uint64, edges ...trieEdge) *trieNode {
	return &trieNode{exported: true, address: addr, edges: edges}
}

func branch(edges ...trieEdge) *trieNode { return &trieNode{edges: edges} }

func TestParseTrieReportsTerminalsInOrder(t *testing.T) {
	for _, tc := range []struct {
		name string
		root *trieNode
	}{
		{"empty", branch()},
		{"exported root", exportAt(0x1)},
		{"terminal with children and sibling order", branch(
			trieEdge{"_a", exportAt(0x10, trieEdge{"b", exportAt(0x20)})},
			trieEdge{"_c", branch(
				trieEdge{"x", exportAt(0x30)},
				trieEdge{"y", exportAt(0x40, trieEdge{"z", exportAt(0x50)})},
			)},
		)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, want := encodeTrie(t, tc.root)
			nodes, err := ParseTrie(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if len(nodes) != len(want) {
				t.Fatalf("ParseTrie returned %d nodes, want %d", len(nodes), len(want))
			}
			for i, n := range nodes {
				if string(n.Data) != want[i].name || n.Offset != want[i].offset {
					t.Errorf("node %d = %q at %#x, want %q at %#x", i, n.Data, n.Offset, want[i].name, want[i].offset)
				}
			}
		})
	}
}

func TestParseTrieExports(t *testing.T) {
	root := branch(
		trieEdge{"_a", exportAt(0x10, trieEdge{"b", exportAt(0x20)})},
		trieEdge{"_c", exportAt(0x30)},
	)
	data, _ := encodeTrie(t, root)
	exports, err := ParseTrieExports(bytes.NewReader(data), 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name string
		addr uint64
	}{{"_a", 0x1010}, {"_ab", 0x1020}, {"_c", 0x1030}}
	if len(exports) != len(want) {
		t.Fatalf("ParseTrieExports returned %d exports, want %d", len(exports), len(want))
	}
	for i, e := range exports {
		if e.Name != want[i].name || e.Address != want[i].addr {
			t.Errorf("export %d = %s at %#x, want %s at %#x", i, e.Name, e.Address, want[i].name, want[i].addr)
		}
	}
}

func TestParseTrieReportsTruncatedChild(t *testing.T) {
	data, _ := encodeTrie(t, branch(trieEdge{"_a", branch(trieEdge{"b", exportAt(0x20)})}))
	nodes, err := ParseTrie(bytes.NewReader(data[:len(data)-2]))
	if err == nil {
		t.Fatalf("truncated trie parsed into %d nodes", len(nodes))
	}
	if nodes != nil {
		t.Errorf("failed parse returned %d nodes, want none", len(nodes))
	}
	if !strings.Contains(err.Error(), "recursive call") {
		t.Errorf("error %q does not name the failing child", err)
	}
}

// radixTrie builds a compressed trie over sorted, unique names, exporting each
// at its index.
func radixTrie(names []string, next *uint64) *trieNode {
	n := &trieNode{}
	i := 0
	if len(names) > 0 && names[0] == "" {
		n.exported, n.address = true, *next
		*next++
		i = 1
	}
	for i < len(names) {
		j := i + 1
		for j < len(names) && names[j][0] == names[i][0] {
			j++
		}
		group := names[i:j]
		prefix := group[0]
		for _, name := range group[1:] {
			for !strings.HasPrefix(name, prefix) {
				prefix = prefix[:len(prefix)-1]
			}
		}
		rest := make([]string, len(group))
		for k, name := range group {
			rest[k] = name[len(prefix):]
		}
		n.edges = append(n.edges, trieEdge{prefix, radixTrie(rest, next)})
		i = j
	}
	return n
}

func BenchmarkParseTrie(b *testing.B) {
	prefixes := []string{"_NS", "_UI", "_CF", "_OBJC_CLASS_$_", "_OBJC_METACLASS_$_", "_$s10Foundation", "_kCF", "_os_log"}
	var names []string
	for i := 0; i < 20000; i++ {
		names = append(names, fmt.Sprintf("%sWidget%d_%s%d", prefixes[i%len(prefixes)], i%700, strings.Repeat("x", i%5), i))
	}
	sort.Strings(names)
	var next uint64
	data, want := encodeTrieOffsets(radixTrie(names, &next), 4)
	if data == nil || len(want) != len(names) {
		b.Fatal("could not encode the benchmark trie")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseTrie(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
