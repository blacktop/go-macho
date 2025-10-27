package swiftdemangle

import (
	"fmt"
	"strconv"
	"strings"
)

type formatContext struct {
	genericNames   map[int]map[int]string
	genericOrdinal map[int]int
}

// Format renders the demangled representation of a node.
func Format(node *Node) string {
	ctx := &formatContext{
		genericNames:   make(map[int]map[int]string),
		genericOrdinal: make(map[int]int),
	}
	return ctx.format(node)
}

func (ctx *formatContext) format(node *Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case KindIdentifier, KindModule:
		return node.Text
	case KindStructure, KindClass, KindEnum, KindProtocol, KindTypeAlias:
		var parts []string
		for _, child := range node.Children {
			if formatted := ctx.format(child); formatted != "" {
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
			elems = append(elems, ctx.format(child))
		}
		return "(" + strings.Join(elems, ", ") + ")"
	case KindEmptyList:
		return "()"
	case KindArgumentTuple:
		var elems []string
		for _, child := range node.Children {
			elems = append(elems, ctx.format(child))
		}
		return "(" + strings.Join(elems, ", ") + ")"
	case KindArgument:
		var typ string
		if len(node.Children) > 0 {
			typ = ctx.format(node.Children[0])
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
			return ctx.format(node.Children[0])
		}
		return ""
	case KindAccessor:
		if len(node.Children) == 0 {
			return node.Text
		}
		variable := node.Children[0]
		varName := ctx.variableName(variable)
		varType := ctx.variableType(variable)
		label := node.Text
		if varType != "" {
			return fmt.Sprintf("%s.%s : %s", varName, label, varType)
		}
		return fmt.Sprintf("%s.%s", varName, label)
	case KindPropertyDescriptor:
		if len(node.Children) == 0 {
			return "property descriptor"
		}
		varName := ctx.variableName(node.Children[0])
		varType := ctx.variableType(node.Children[0])
		if varType != "" {
			return fmt.Sprintf("property descriptor for %s : %s", varName, varType)
		}
		return fmt.Sprintf("property descriptor for %s", varName)
	case KindProtocolDescriptor:
		if len(node.Children) == 0 {
			return "protocol descriptor"
		}
		return "protocol descriptor for " + ctx.format(node.Children[0])
	case KindNominalTypeDescriptor:
		if len(node.Children) == 0 {
			return "nominal type descriptor"
		}
		return "nominal type descriptor for " + ctx.format(node.Children[0])
	case KindMethodDescriptor:
		if len(node.Children) == 0 {
			return "method descriptor"
		}
		return "method descriptor for " + ctx.format(node.Children[0])
	case KindStatic:
		if len(node.Children) == 0 {
			return "static"
		}
		return "static " + ctx.format(node.Children[0])
	case KindTypeMetadataAccessFunction:
		return ctx.formatSingleChildDescription("type metadata accessor for ", node)
	case KindCanonicalSpecializedGenericTypeMetadataAccessFunction:
		return ctx.formatSingleChildDescription("canonical specialized generic type metadata accessor for ", node)
	case KindTypeMetadataInstantiationFunction:
		return ctx.formatSingleChildDescription("type metadata instantiation function for ", node)
	case KindTypeMetadataInstantiationCache:
		return ctx.formatSingleChildDescription("type metadata instantiation cache for ", node)
	case KindFullTypeMetadata:
		return ctx.formatSingleChildDescription("full type metadata for ", node)
	case KindTypeMetadataSingletonInitializationCache:
		return ctx.formatSingleChildDescription("type metadata singleton initialization cache for ", node)
	case KindTypeMetadataCompletionFunction:
		return ctx.formatSingleChildDescription("type metadata completion function for ", node)
	case KindClassMetadataBaseOffset:
		return ctx.formatSingleChildDescription("class metadata base offset for ", node)
	case KindObjCResilientClassStub:
		return ctx.formatSingleChildDescription("ObjC resilient class stub for ", node)
	case KindFullObjCResilientClassStub:
		return ctx.formatSingleChildDescription("full ObjC resilient class stub for ", node)
	case KindMethodLookupFunction:
		return ctx.formatSingleChildDescription("method lookup function for ", node)
	case KindObjCMetadataUpdateFunction:
		return ctx.formatSingleChildDescription("ObjC metadata update function for ", node)
	case KindCanonicalPrespecializedGenericTypeCachingOnceToken:
		return ctx.formatSingleChildDescription("flag for loading of canonical specialized generic type metadata for ", node)
	case KindOptional:
		if len(node.Children) > 0 {
			return ctx.format(node.Children[0]) + "?"
		}
		return "?"
	case KindImplicitlyUnwrappedOptional:
		if len(node.Children) > 0 {
			return ctx.format(node.Children[0]) + "!"
		}
		return "!"
	case KindArray:
		if len(node.Children) == 0 {
			return "[]"
		}
		return "[" + ctx.format(node.Children[0]) + "]"
	case KindDictionary:
		if len(node.Children) < 2 {
			return "[:]"
		}
		return "[" + ctx.format(node.Children[0]) + " : " + ctx.format(node.Children[1]) + "]"
	case KindSet:
		if len(node.Children) == 0 {
			return "Set<>"
		}
		return "Set<" + ctx.format(node.Children[0]) + ">"
	case KindDependentGenericParamType:
		if name, ok := ctx.formatDependentGenericParam(node); ok {
			return name
		}
		if len(node.Children) >= 2 {
			return fmt.Sprintf("τ_%s_%s", ctx.format(node.Children[0]), ctx.format(node.Children[1]))
		}
		return "τ"
	case KindDependentAssociatedTypeRef:
		if node.Text != "" {
			if node.Text == "ObjectiveCType" {
				return "_ObjectiveCType"
			}
			return node.Text
		}
		if len(node.Children) > 0 {
			return ctx.format(node.Children[0])
		}
		return "assoc"
	case KindDependentMemberType:
		if len(node.Children) >= 2 {
			base := node.Children[0]
			member := node.Children[1]
			memberName := ctx.format(member)
			if memberName == "ObjectiveCType" {
				memberName = "_ObjectiveCType"
			}
			if memberName == "_ObjectiveCType" {
				if depth, index, ok := parseGenericParamIndices(base); ok {
					// Bridge associated types hang off the primary generic parameter.
					index = 0
					return ctx.genericName(depth, index) + "." + memberName
				}
			}
			return ctx.format(base) + "." + memberName
		}
		return "dependent"
	case KindInOut:
		if len(node.Children) == 0 {
			return "inout"
		}
		return "inout " + ctx.format(node.Children[0])
	case KindIndex:
		return node.Text
	case KindGenericArgs:
		var elems []string
		for _, child := range node.Children {
			elems = append(elems, ctx.format(child))
		}
		return "<" + strings.Join(elems, ", ") + ">"
	case KindBoundGeneric:
		if len(node.Children) == 0 {
			return ""
		}
		base := ctx.format(node.Children[0])
		var args []string
		if len(node.Children) > 1 {
			for _, child := range node.Children[1].Children {
				args = append(args, ctx.format(child))
			}
		}
		if len(args) == 0 {
			return base
		}
		return base + "<" + strings.Join(args, ", ") + ">"
	case KindFunction:
		if len(node.Children) < 2 {
			return ""
		}
		params := ctx.format(node.Children[0])
		result := ctx.format(node.Children[1])
		if result == "" && len(node.Children[1].Children) == 0 && node.Children[1].Kind == KindTuple {
			result = "()"
		}
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
			parts = append(parts, ctx.format(child))
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

func (ctx *formatContext) formatDependentGenericParam(node *Node) (string, bool) {
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
	return ctx.genericName(depth, index), true
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

func (ctx *formatContext) formatSingleChildDescription(prefix string, node *Node) string {
	if node == nil || len(node.Children) == 0 {
		return prefix
	}
	return prefix + ctx.format(node.Children[0])
}

func (ctx *formatContext) variableName(n *Node) string {
	if n == nil {
		return ""
	}
	if n.Text != "" {
		return n.Text
	}
	return ctx.format(n)
}

func (ctx *formatContext) variableType(n *Node) string {
	if n == nil || len(n.Children) == 0 {
		return ""
	}
	return ctx.format(n.Children[0])
}

func (ctx *formatContext) genericName(depth, index int) string {
	namesForDepth := ctx.genericNames[depth]
	if namesForDepth == nil {
		namesForDepth = make(map[int]string)
		ctx.genericNames[depth] = namesForDepth
	}
	if name, ok := namesForDepth[index]; ok {
		return name
	}
	ordinal := ctx.genericOrdinal[depth]
	ctx.genericOrdinal[depth] = ordinal + 1
	name := renderGenericParameter(depth, ordinal)
	namesForDepth[index] = name
	return name
}

func parseGenericParamIndices(node *Node) (depth int, index int, ok bool) {
	if node == nil || node.Kind != KindDependentGenericParamType {
		return 0, 0, false
	}
	if len(node.Children) < 2 {
		return 0, 0, false
	}
	d, ok := parseIndexNodeValue(node.Children[0])
	if !ok {
		return 0, 0, false
	}
	i, ok := parseIndexNodeValue(node.Children[1])
	if !ok {
		return 0, 0, false
	}
	return d, i, true
}
