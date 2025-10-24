package swiftdemangle

// NodeKind identifies the semantic role of a node in the Swift demangling AST.
type NodeKind string

const (
	// Generic utility nodes.
	KindUnknown    NodeKind = "unknown"
	KindIdentifier NodeKind = "identifier"
	KindModule     NodeKind = "module"

	// Nominal types and related contexts.
	KindStructure NodeKind = "struct"
	KindClass     NodeKind = "class"
	KindEnum      NodeKind = "enum"
	KindProtocol  NodeKind = "protocol"
	KindTypeAlias NodeKind = "typealias"

	// Type composition nodes.
	KindTuple         NodeKind = "tuple"
	KindFunction      NodeKind = "function"
	KindArgumentTuple NodeKind = "argumentTuple"
	KindReturnType    NodeKind = "returnType"
	KindMetatype      NodeKind = "metatype"
	KindExistential   NodeKind = "existential"
	KindGenericArgs   NodeKind = "genericArguments"
	KindBoundGeneric  NodeKind = "boundGeneric"
	KindArgument      NodeKind = "argument"

	// Sugared forms.
	KindOptional                    NodeKind = "optional"
	KindImplicitlyUnwrappedOptional NodeKind = "implicitlyUnwrappedOptional"
	KindArray                       NodeKind = "array"
	KindDictionary                  NodeKind = "dictionary"
	KindSet                         NodeKind = "set"
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
