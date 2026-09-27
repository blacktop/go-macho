package swift_test

import (
	"testing"

	"github.com/blacktop/go-macho/types/swift"
)

func TestSuperclassFormatting(t *testing.T) {
	for _, tc := range []struct {
		name, module string
		resilient    bool
	}{
		{name: "ordinary", module: "ExternalSwiftView"},
		{name: "resilient", module: "ExternalSwiftView", resilient: true},
		{name: "resilient_unqualified", resilient: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			superclass := "SwiftBaseVC"
			if tc.module != "" {
				superclass = tc.module + "." + superclass
			}
			class := swift.Class{SuperClass: superclass}
			if tc.resilient {
				class.Flags = swift.ContextDescriptorFlags(1 << (16 + swift.Class_HasResilientSuperclass))
				class.ResilientSuperclass = &swift.ResilientSuperclass{Type: &swift.Type{
					Name: "SwiftBaseVC", Parent: &swift.Type{Name: tc.module},
				}}
			}
			typ := swift.Type{
				Kind: swift.CDKindClass, Name: "SwiftChildVC2", Type: class,
				Parent: &swift.Type{Name: "ChildSwiftView", Parent: &swift.Type{}},
			}
			want := "class ChildSwiftView.SwiftChildVC2: " + superclass + " {}"
			if got := typ.String(); got != want {
				t.Errorf("String: got %q; want %q", got, want)
			}
			if got := typ.Verbose(); got != "// 0x0\n"+want {
				t.Errorf("Verbose: got %q; want %q", got, "// 0x0\n"+want)
			}
		})
	}
}

func TestResilientSuperclassMissingContext(t *testing.T) {
	for _, base := range []*swift.ResilientSuperclass{
		nil,
		{},
		{Type: &swift.Type{}},
		{Type: &swift.Type{Name: "Fallback"}},
	} {
		c := swift.Class{SuperClass: "Fallback", ResilientSuperclass: base}
		c.Flags = swift.ContextDescriptorFlags(1 << (16 + swift.Class_HasResilientSuperclass))
		typ := swift.Type{Kind: swift.CDKindClass, Name: "Leaf", Type: c}
		if got, want := typ.String(), "class Leaf: Fallback {}"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestSuperclassName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class swift.Class
		want  string
	}{
		{"descriptor fallback", swift.Class{ResilientSuperclass: &swift.ResilientSuperclass{Type: &swift.Type{Name: "Parent", Parent: &swift.Type{Name: "Base"}}}}, "Base.Parent"},
		{"generic type preferred", swift.Class{SuperClass: "Base.Parent<Int>", ResilientSuperclass: &swift.ResilientSuperclass{Type: &swift.Type{Name: "Parent"}}}, "Base.Parent<Int>"},
		{"bound descriptor", swift.Class{SuperClass: "_$s4Base6ParentCMn"}, "_$s4Base6ParentC"},
		{"demangled descriptor", swift.Class{SuperClass: "nominal type descriptor for Base.Parent"}, "Base.Parent"},
		{"no superclass", swift.Class{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.class.SuperclassName(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
