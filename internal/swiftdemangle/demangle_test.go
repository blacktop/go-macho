package swiftdemangle

import (
	"fmt"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

const forceBridgeSymbol = "_$ss21_ObjectiveCBridgeableP016_forceBridgeFromA1C_6resulty01_A5CTypeQz_xSgztFZTq"

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

func TestDemangleObjectiveCBridgeableForceBridgeProfile(t *testing.T) {
	if os.Getenv("GO_MACHO_SWIFT_PROFILE_FORCEBRIDGE") == "" {
		t.Skip("set GO_MACHO_SWIFT_PROFILE_FORCEBRIDGE=1 to run profiling test")
	}
	prof, err := os.CreateTemp("", "forcebridge-*.pprof")
	if err != nil {
		t.Fatalf("failed to create profile file: %v", err)
	}
	t.Logf("CPU profile will be written to %s", prof.Name())
	if err := pprof.StartCPUProfile(prof); err != nil {
		prof.Close()
		t.Fatalf("failed to start cpu profile: %v", err)
	}
	t.Cleanup(func() {
		pprof.StopCPUProfile()
		prof.Close()
		t.Logf("CPU profile saved to %s", prof.Name())
	})
	done := make(chan struct{})
	var (
		out    string
		node   *Node
		demErr error
	)
	go func() {
		out, node, demErr = Demangle(forceBridgeSymbol)
		close(done)
	}()
	select {
	case <-time.After(10 * time.Second):
		t.Fatalf("demangle of %s timed out; inspect %s", forceBridgeSymbol, prof.Name())
	case <-done:
	}
	if demErr != nil {
		t.Fatalf("Demangle returned error: %v", demErr)
	}
	if node == nil {
		t.Fatalf("Demangle returned nil node")
	}
	t.Logf("demangled symbol: %s", out)
}

func TestDemangleObjectiveCBridgeableForceBridge(t *testing.T) {
	out, _, err := Demangle(forceBridgeSymbol)
	if err != nil {
		t.Fatalf("Demangle failed: %v", err)
	}
	const want = "method descriptor for static Swift._ObjectiveCBridgeable._forceBridgeFromObjectiveC(_: A._ObjectiveCType, result: inout A?) -> ()"
	if out != want {
		t.Fatalf("unexpected demangle result:\n got  %q\n want %q", out, want)
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

func TestDemangleAccessorsAndDescriptors(t *testing.T) {
	d := New(nil)
	cases := []struct {
		mangled string
		want    string
	}{
		{"_$s16DemangleFixtures7CounterC5valueSivg", "DemangleFixtures.Counter.value.getter : Swift.Int"},
		{"_$s16DemangleFixtures7CounterC5valueSivs", "DemangleFixtures.Counter.value.setter : Swift.Int"},
		{"_$s16DemangleFixtures7CounterC5valueSivpMV", "property descriptor for DemangleFixtures.Counter.value : Swift.Int"},
		{"_$sScAMp", "protocol descriptor for Swift.Actor"},
		{"_$sScA15unownedExecutorScevgTq", "method descriptor for Swift.Actor.unownedExecutor.getter : Swift.UnownedSerialExecutor"},
		{"_$s16DemangleFixtures7CounterC5valueACSi_tcfC", "DemangleFixtures.Counter.__allocating_init(value: Swift.Int) -> DemangleFixtures.Counter"},
		{"_$s16DemangleFixtures7CounterC5valueACSi_tcfc", "DemangleFixtures.Counter.init(value: Swift.Int) -> DemangleFixtures.Counter"},
		{"_$s16DemangleFixtures15ObjCBridgeClassC7payloadAA5OuterV5InnerVvg", "DemangleFixtures.ObjCBridgeClass.payload.getter : DemangleFixtures.Outer.Inner"},
		{"_$s16DemangleFixtures15ObjCBridgeClassC5label7payloadACSS_AA5OuterV5InnerVtcfC", "DemangleFixtures.ObjCBridgeClass.__allocating_init(label: Swift.String, payload: DemangleFixtures.Outer.Inner) -> DemangleFixtures.ObjCBridgeClass"},
		{"_$s16DemangleFixtures15ObjCBridgeClassC12payloadValueSiyF", "DemangleFixtures.ObjCBridgeClass.payloadValue() -> Swift.Int"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.mangled, func(t *testing.T) {
			out, _, err := d.DemangleString([]byte(tc.mangled))
			if err != nil {
				t.Fatalf("DemangleString failed: %v", err)
			}
			if out != tc.want {
				t.Fatalf("unexpected demangle output: got %q want %q", out, tc.want)
			}
		})
	}
}

func TestDemangleMetadataSuffixes(t *testing.T) {
	d := New(nil)
	cases := []struct {
		mangled string
		want    string
	}{
		{"$sSiMa", "type metadata accessor for Swift.Int"},
		{"$sSaMb", "canonical specialized generic type metadata accessor for Swift.Array"},
		{"$sSiMf", "full type metadata for Swift.Int"},
		{"$sSiMi", "type metadata instantiation function for Swift.Int"},
		{"$sSiMI", "type metadata instantiation cache for Swift.Int"},
		{"$sSiMl", "type metadata singleton initialization cache for Swift.Int"},
		{"$sSiMr", "type metadata completion function for Swift.Int"},
		{"$sSiMo", "class metadata base offset for Swift.Int"},
		{"$sSiMs", "ObjC resilient class stub for Swift.Int"},
		{"$sSiMt", "full ObjC resilient class stub for Swift.Int"},
		{"$sSiMu", "method lookup function for Swift.Int"},
		{"$sSiMU", "ObjC metadata update function for Swift.Int"},
		{"$sSiMz", "flag for loading of canonical specialized generic type metadata for Swift.Int"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.mangled, func(t *testing.T) {
			out, _, err := d.DemangleString([]byte(tc.mangled))
			if err != nil {
				t.Fatalf("DemangleString failed: %v", err)
			}
			if out != tc.want {
				t.Fatalf("unexpected demangle output: got %q want %q", out, tc.want)
			}
		})
	}
}
