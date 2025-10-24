package swiftdemangle

import (
	"fmt"
	"testing"
)

type stubResolver struct {
	nodes map[int32]*Node
	calls []struct {
		control  byte
		offset   int32
		refIndex int
	}
}

func (s *stubResolver) ResolveType(control byte, offset int32, refIndex int) (*Node, error) {
	s.calls = append(s.calls, struct {
		control  byte
		offset   int32
		refIndex int
	}{control: control, offset: offset, refIndex: refIndex})
	if node, ok := s.nodes[offset]; ok {
		return node.Clone(), nil
	}
	return nil, fmt.Errorf("unknown symbolic reference offset %d", offset)
}

func TestDemangleStandardType(t *testing.T) {
	d := New(nil)
	node, err := d.DemangleType([]byte("Si"))
	if err != nil {
		t.Fatalf("DemangleType failed: %v", err)
	}
	if got, want := Format(node), "Swift.Int"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
}

func TestDemangleNominalStruct(t *testing.T) {
	d := New(nil)
	node, err := d.DemangleType([]byte("8MyModule6MyTypeV"))
	if err != nil {
		t.Fatalf("DemangleType failed: %v", err)
	}
	if node.Kind != KindStructure {
		t.Fatalf("unexpected node kind %q", node.Kind)
	}
	if got, want := Format(node), "MyModule.MyType"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
}

func TestDemangleTuple(t *testing.T) {
	d := New(nil)
	node, err := d.DemangleType([]byte("Si_Sit"))
	if err != nil {
		t.Fatalf("DemangleType failed: %v", err)
	}
	if node.Kind != KindTuple {
		t.Fatalf("unexpected node kind %q", node.Kind)
	}
	if got, want := Format(node), "(Swift.Int, Swift.Int)"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
}

func TestDemangleTupleWithSubstitution(t *testing.T) {
	d := New(nil)
	node, err := d.DemangleType([]byte("Si_S_t"))
	if err != nil {
		t.Fatalf("DemangleType failed: %v", err)
	}
	if node.Kind != KindTuple {
		t.Fatalf("unexpected node kind %q", node.Kind)
	}
	if got, want := Format(node), "(Swift.Int, Swift.Int)"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
}

func TestDemangleSymbolicReference(t *testing.T) {
	resolver := &stubResolver{
		nodes: map[int32]*Node{
			0x1234: func() *Node {
				node := NewNode(KindStructure, "ResolvedType")
				node.Append(NewNode(KindModule, "MyModule"))
				return node
			}(),
		},
	}

	d := New(resolver)
	input := []byte{0x01, 0x34, 0x12, 0x00, 0x00}
	node, err := d.DemangleType(input)
	if err != nil {
		t.Fatalf("DemangleType failed: %v", err)
	}
	if got, want := Format(node), "MyModule.ResolvedType"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
	if len(resolver.calls) != 1 {
		t.Fatalf("expected resolver to be invoked once, got %d", len(resolver.calls))
	}
	call := resolver.calls[0]
	if call.control != 0x01 {
		t.Fatalf("unexpected control %#x", call.control)
	}
	if call.offset != 0x1234 {
		t.Fatalf("unexpected offset %x", call.offset)
	}
	if call.refIndex != 1 {
		t.Fatalf("unexpected ref index %d", call.refIndex)
	}
}

func TestDemangleGenericArray(t *testing.T) {
	d := New(nil)
	node, err := d.DemangleType([]byte("SaySiG"))
	if err != nil {
		t.Fatalf("DemangleType failed: %v", err)
	}
	if got, want := Format(node), "[Swift.Int]"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
}

func TestDemangleOptional(t *testing.T) {
	d := New(nil)
	node, err := d.DemangleType([]byte("SqySi_G"))
	if err != nil {
		t.Fatalf("DemangleType failed: %v", err)
	}
	if got, want := Format(node), "Swift.Int?"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
}

func TestFormatSetSugar(t *testing.T) {
	base := NewNode(KindStructure, "Set")
	base.Append(NewNode(KindModule, "Swift"))
	element := NewNode(KindStructure, "String")
	element.Append(NewNode(KindModule, "Swift"))
	args := NewNode(KindGenericArgs, "")
	args.Append(element)
	bound := NewNode(KindBoundGeneric, "")
	bound.Append(base, args)
	sugared := applyTypeSugar(bound)
	if got, want := Format(sugared), "Set<Swift.String>"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
}
func TestDemangleDictionary(t *testing.T) {
	d := New(nil)
	node, err := d.DemangleType([]byte("SDySSSiG"))
	if err != nil {
		t.Fatalf("DemangleType failed: %v", err)
	}
	if got, want := Format(node), "[Swift.String : Swift.Int]"; got != want {
		t.Fatalf("Format mismatch: got %q, want %q", got, want)
	}
}

func TestDemangleFunctionTypes(t *testing.T) {
	cases := []struct {
		mangled string
		want    string
	}{
		{"SbSi_SStc", "(Swift.Int, Swift.String) -> Swift.Bool"},
		{"SSSiKc", "(Swift.Int) throws -> Swift.String"},
		{"SbSiYac", "(Swift.Int) async -> Swift.Bool"},
		{"SbSi_SStYaKc", "(Swift.Int, Swift.String) async throws -> Swift.Bool"},
	}

	d := New(nil)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.mangled, func(t *testing.T) {
			node, err := d.DemangleType([]byte(tc.mangled))
			if err != nil {
				t.Fatalf("DemangleType failed: %v", err)
			}
			if got := Format(node); got != tc.want {
				t.Fatalf("Format mismatch: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDemangleStringHelper(t *testing.T) {
	d := New(nil)
	out, node, err := d.DemangleString([]byte("Si"))
	if err != nil {
		t.Fatalf("DemangleString failed: %v", err)
	}
	if out != "Swift.Int" {
		t.Fatalf("unexpected output %q", out)
	}
	if node == nil || Format(node) != out {
		t.Fatalf("unexpected node format %v", node)
	}
}

func TestDemangleSymbolFunction(t *testing.T) {
	d := New(nil)
	symbol := "$s13lockdownmoded18LockdownModeServerC8listener_25shouldAcceptNewConnectionSbSo13NSXPCListenerC_So15NSXPCConnectionCtF"
	out, node, err := d.DemangleString([]byte(symbol))
	if err != nil {
		t.Fatalf("DemangleString failed: %v", err)
	}
	want := "lockdownmoded.LockdownModeServer.listener(_: __C.NSXPCListener, shouldAcceptNewConnection: __C.NSXPCConnection) -> Swift.Bool"
	if out != want {
		t.Fatalf("unexpected symbol output: got %q want %q", out, want)
	}
	if node == nil || node.Kind != KindFunction {
		t.Fatalf("unexpected node kind %#v", node)
	}
}

func TestDemangleOptionalTupleType(t *testing.T) {
	d := New(nil)
	out, _, err := d.DemangleString([]byte("Si_SStSg"))
	if err != nil {
		t.Fatalf("DemangleString failed: %v", err)
	}
	if got, want := out, "(Swift.Int, Swift.String)?"; got != want {
		t.Fatalf("unexpected optional tuple output: got %q want %q", got, want)
	}
}
