package swiftdemangle

import "fmt"

// PrintTree dumps the node tree (used for debugging).
func PrintTree(node *Node, indent int) {
	if node == nil {
		return
	}
	prefix := ""
	for i := 0; i < indent; i++ {
		prefix += "  "
	}
	fmt.Printf("%s- %s", prefix, node.Kind)
	if node.Text != "" {
		fmt.Printf(" (%s)", node.Text)
	}
	fmt.Println()
	for _, child := range node.Children {
		PrintTree(child, indent+1)
	}
}
