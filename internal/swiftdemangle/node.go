package swiftdemangle

//go:generate go run ./internal/swiftdemangle/cmd/gennodes

// NodeKind identifies the semantic role of a node in the Swift demangling AST.
type NodeKind string

const (
	// Synthetic kinds not present in DemangleNodes.def.
	KindUnknown                     NodeKind = "unknown"
	KindGenericArgs                 NodeKind = "genericArguments"
	KindArgument                    NodeKind = "argument"
	KindBoundGeneric                NodeKind = "boundGeneric"
	KindOptional                    NodeKind = "optional"
	KindImplicitlyUnwrappedOptional NodeKind = "implicitlyUnwrappedOptional"
	KindArray                       NodeKind = "array"
	KindDictionary                  NodeKind = "dictionary"
	KindSet                         NodeKind = "set"
	KindAccessor                    NodeKind = "accessor"
)

// NodeFlags holds auxiliary attributes that tweak formatting semantics.
type NodeFlags struct {
	Async    bool
	Throws   bool
	Escaping bool
}

// Node represents a demangled element.
type Node struct {
	Kind     NodeKind
	Text     string
	Children []*Node
	Flags    NodeFlags
}

// NewNode creates a new node with the given kind and text.
func NewNode(kind NodeKind, text string) *Node {
	return &Node{
		Kind: kind,
		Text: text,
	}
}

// Append appends child nodes to the receiver.
func (n *Node) Append(children ...*Node) {
	if len(children) == 0 {
		return
	}
	n.Children = append(n.Children, children...)
}

// Clone shallow-copies the node. Children references are copied as-is.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	out := &Node{
		Kind:  n.Kind,
		Text:  n.Text,
		Flags: n.Flags,
	}
	if len(n.Children) > 0 {
		out.Children = append([]*Node(nil), n.Children...)
	}
	return out
}
