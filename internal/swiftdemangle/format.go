package swiftdemangle

import "strings"

// Format renders the demangled representation of a node.
func Format(node *Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case KindIdentifier, KindModule:
		return node.Text
	case KindStructure, KindClass, KindEnum, KindProtocol, KindTypeAlias:
		var parts []string
		for _, child := range node.Children {
			if formatted := Format(child); formatted != "" {
				parts = append(parts, formatted)
			}
		}
		if node.Text != "" {
			parts = append(parts, node.Text)
		}
		return strings.Join(parts, ".")
	case KindTuple:
		var elems []string
		for _, child := range node.Children {
			elems = append(elems, Format(child))
		}
		return "(" + strings.Join(elems, ", ") + ")"
	case KindArgumentTuple:
		var elems []string
		for _, child := range node.Children {
			elems = append(elems, Format(child))
		}
		return "(" + strings.Join(elems, ", ") + ")"
	case KindArgument:
		var typ string
		if len(node.Children) > 0 {
			typ = Format(node.Children[0])
		}
		label := node.Text
		if label == "" {
			label = "_"
		}
		if typ == "" {
			return label
		}
		return label + ": " + typ
	case KindOptional:
		if len(node.Children) > 0 {
			return Format(node.Children[0]) + "?"
		}
		return "?"
	case KindImplicitlyUnwrappedOptional:
		if len(node.Children) > 0 {
			return Format(node.Children[0]) + "!"
		}
		return "!"
	case KindArray:
		if len(node.Children) == 0 {
			return "[]"
		}
		return "[" + Format(node.Children[0]) + "]"
	case KindDictionary:
		if len(node.Children) < 2 {
			return "[:]"
		}
		return "[" + Format(node.Children[0]) + " : " + Format(node.Children[1]) + "]"
	case KindSet:
		if len(node.Children) == 0 {
			return "Set<>"
		}
		return "Set<" + Format(node.Children[0]) + ">"
	case KindGenericArgs:
		var elems []string
		for _, child := range node.Children {
			elems = append(elems, Format(child))
		}
		return "<" + strings.Join(elems, ", ") + ">"
	case KindBoundGeneric:
		if len(node.Children) == 0 {
			return ""
		}
		base := node.Children[0]
		var args []string
		if len(node.Children) > 1 {
			for _, child := range node.Children[1].Children {
				args = append(args, Format(child))
			}
		}
		if len(args) == 0 {
			return Format(base)
		}
		return Format(base) + "<" + strings.Join(args, ", ") + ">"
	case KindFunction:
		if len(node.Children) < 2 {
			return ""
		}
		params := Format(node.Children[0])
		result := Format(node.Children[1])
		if node.Text != "" {
			var extras []string
			if node.Flags.Async {
				extras = append(extras, "async")
			}
			if node.Flags.Throws {
				extras = append(extras, "throws")
			}
			suffix := ""
			if len(extras) > 0 {
				suffix = " " + strings.Join(extras, " ")
			}
			return node.Text + params + suffix + " -> " + result
		}
		parts := []string{params}
		if node.Flags.Async {
			parts = append(parts, "async")
		}
		if node.Flags.Throws {
			parts = append(parts, "throws")
		}
		if len(parts) == 1 {
			return params + " -> " + result
		}
		return strings.Join(parts, " ") + " -> " + result
	default:
		if len(node.Children) == 0 {
			return node.Text
		}
		var parts []string
		for _, child := range node.Children {
			parts = append(parts, Format(child))
		}
		if node.Text != "" {
			parts = append([]string{node.Text}, parts...)
		}
		return strings.Join(parts, " ")
	}
}

// String implements fmt.Stringer for convenience.
func (n *Node) String() string {
	return Format(n)
}
