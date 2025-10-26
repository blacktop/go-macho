package swiftdemangle

import (
	"fmt"
	"strconv"
	"strings"
)

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
	case KindVariable:
		if node.Text != "" {
			return node.Text
		}
		if len(node.Children) > 0 {
			return Format(node.Children[0])
		}
		return ""
	case KindAccessor:
		if len(node.Children) == 0 {
			return node.Text
		}
		variable := node.Children[0]
		varName := variableName(variable)
		varType := variableType(variable)
		label := node.Text
		if varType != "" {
			return fmt.Sprintf("%s.%s : %s", varName, label, varType)
		}
		return fmt.Sprintf("%s.%s", varName, label)
	case KindPropertyDescriptor:
		if len(node.Children) == 0 {
			return "property descriptor"
		}
		varName := variableName(node.Children[0])
		varType := variableType(node.Children[0])
		if varType != "" {
			return fmt.Sprintf("property descriptor for %s : %s", varName, varType)
		}
		return fmt.Sprintf("property descriptor for %s", varName)
	case KindProtocolDescriptor:
		if len(node.Children) == 0 {
			return "protocol descriptor"
		}
		return "protocol descriptor for " + Format(node.Children[0])
	case KindNominalTypeDescriptor:
		if len(node.Children) == 0 {
			return "nominal type descriptor"
		}
		return "nominal type descriptor for " + Format(node.Children[0])
	case KindMethodDescriptor:
		if len(node.Children) == 0 {
			return "method descriptor"
		}
		return "method descriptor for " + Format(node.Children[0])
	case KindTypeMetadataAccessFunction:
		return formatSingleChildDescription("type metadata accessor for ", node)
	case KindCanonicalSpecializedGenericTypeMetadataAccessFunction:
		return formatSingleChildDescription("canonical specialized generic type metadata accessor for ", node)
	case KindTypeMetadataInstantiationFunction:
		return formatSingleChildDescription("type metadata instantiation function for ", node)
	case KindTypeMetadataInstantiationCache:
		return formatSingleChildDescription("type metadata instantiation cache for ", node)
	case KindFullTypeMetadata:
		return formatSingleChildDescription("full type metadata for ", node)
	case KindTypeMetadataSingletonInitializationCache:
		return formatSingleChildDescription("type metadata singleton initialization cache for ", node)
	case KindTypeMetadataCompletionFunction:
		return formatSingleChildDescription("type metadata completion function for ", node)
	case KindClassMetadataBaseOffset:
		return formatSingleChildDescription("class metadata base offset for ", node)
	case KindObjCResilientClassStub:
		return formatSingleChildDescription("ObjC resilient class stub for ", node)
	case KindFullObjCResilientClassStub:
		return formatSingleChildDescription("full ObjC resilient class stub for ", node)
	case KindMethodLookupFunction:
		return formatSingleChildDescription("method lookup function for ", node)
	case KindObjCMetadataUpdateFunction:
		return formatSingleChildDescription("ObjC metadata update function for ", node)
	case KindCanonicalPrespecializedGenericTypeCachingOnceToken:
		return formatSingleChildDescription("flag for loading of canonical specialized generic type metadata for ", node)
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
	case KindDependentGenericParamType:
		if name, ok := formatDependentGenericParam(node); ok {
			return name
		}
		if len(node.Children) >= 2 {
			return fmt.Sprintf("τ_%s_%s", Format(node.Children[0]), Format(node.Children[1]))
		}
		return "τ"
	case KindDependentAssociatedTypeRef:
		if node.Text != "" {
			return node.Text
		}
		if len(node.Children) > 0 {
			return Format(node.Children[0])
		}
		return "assoc"
	case KindDependentMemberType:
		if len(node.Children) >= 2 {
			return Format(node.Children[0]) + "." + Format(node.Children[1])
		}
		return "dependent"
	case KindIndex:
		return node.Text
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

func formatDependentGenericParam(node *Node) (string, bool) {
	if node == nil || len(node.Children) < 2 {
		return "", false
	}
	depth, ok := parseIndexNodeValue(node.Children[0])
	if !ok {
		return "", false
	}
	index, ok := parseIndexNodeValue(node.Children[1])
	if !ok {
		return "", false
	}
	return renderGenericParameter(depth, index), true
}

func parseIndexNodeValue(node *Node) (int, bool) {
	if node == nil || node.Kind != KindIndex {
		return 0, false
	}
	val, err := strconv.Atoi(node.Text)
	if err != nil {
		return 0, false
	}
	return val, true
}

func renderGenericParameter(depth, index int) string {
	if index < 0 {
		return fmt.Sprintf("τ_%d_%d", depth, index)
	}
	var builder strings.Builder
	val := index
	for {
		builder.WriteByte(byte('A' + (val % 26)))
		val /= 26
		if val == 0 {
			break
		}
	}
	if depth > 0 {
		builder.WriteString(strconv.Itoa(depth))
	}
	return builder.String()
}

func formatSingleChildDescription(prefix string, node *Node) string {
	if node == nil || len(node.Children) == 0 {
		return prefix
	}
	return prefix + Format(node.Children[0])
}

func variableName(n *Node) string {
	if n == nil {
		return ""
	}
	if n.Text != "" {
		return n.Text
	}
	return Format(n)
}

func variableType(n *Node) string {
	if n == nil || len(n.Children) == 0 {
		return ""
	}
	return Format(n.Children[0])
}
