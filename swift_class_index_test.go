package macho

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/blacktop/go-macho/types/swift"
)

func swiftClassFixture(name string, parent string, fields map[string]string) swift.Type {
	typ := swift.Type{Kind: swift.CDKindClass, Name: name}
	if parent != "" {
		typ.Parent = &swift.Type{Kind: swift.CDKindModule, Name: parent}
	}
	if fields != nil {
		typ.Fields = &swift.Field{}
		for fieldName, mangled := range fields {
			typ.Fields.Records = append(typ.Fields.Records,
				swift.FieldRecord{Name: fieldName, MangledType: mangled})
		}
	}
	return typ
}

// linearSwiftFieldTypes is the pre-index reference: scan the catalog in order
// and take the first class whose raw or normalized name is a lookup name.
func linearSwiftFieldTypes(
	types []swift.Type, fullName string, normalize func(string) string,
) map[string]string {
	lookupNames := swiftClassLookupNames(fullName, normalize)
	for i := range types {
		typ := &types[i]
		if typ.Kind != swift.CDKindClass {
			continue
		}
		typeName := fullSwiftTypeName(typ)
		if _, ok := lookupNames[typeName]; !ok {
			if normalize == nil {
				continue
			}
			if _, ok := lookupNames[normalize(typeName)]; !ok {
				continue
			}
		}
		if typ.Fields == nil {
			return nil
		}
		fieldMap := make(map[string]string)
		for _, rec := range typ.Fields.Records {
			if rec.Name == "" || rec.MangledType == "" {
				continue
			}
			fieldMap[rec.Name] = rec.MangledType
		}
		return fieldMap
	}
	return nil
}

// sectionlessSwiftFile cannot parse a type catalog, so any lookup that reaches
// GetSwiftTypes fails with ErrSwiftSectionError.
func sectionlessSwiftFile(autoDemangle bool) *File {
	return &File{swift: make(map[uint64]any), swiftAutoDemangle: autoDemangle}
}

func TestSwiftClassIndexMatchesLinearScan(t *testing.T) {
	demangled := swiftClassFixture("Foo", "Mod", map[string]string{"demangled": "Si"})
	mangled := swiftClassFixture("_TtC3Mod3Foo", "", map[string]string{"mangled": "SS"})
	other := swiftClassFixture("Bar", "Mod", map[string]string{"bar": "Sb"})
	noFields := swiftClassFixture("Empty", "Mod", nil)
	skipped := swiftClassFixture("Skipped", "Mod", map[string]string{"": "Si", "ok": ""})
	structType := swift.Type{Kind: swift.CDKindStruct, Name: "Foo",
		Parent: &swift.Type{Kind: swift.CDKindModule, Name: "Mod"}}

	catalogs := map[string][]swift.Type{
		"demangled first": {structType, demangled, mangled, other, noFields, skipped},
		"mangled first":   {mangled, demangled, other, noFields, skipped},
		"duplicates":      {other, demangled, demangled, mangled},
	}
	lookups := []string{
		"Mod.Foo", "_OBJC_CLASS_$__TtC3Mod3Foo", "_TtC3Mod3Foo", "TtC3Mod3Foo",
		"$s3Mod3FooC", "Mod.Bar", "Mod.Empty", "Mod.Skipped", "Mod.Missing", "",
	}
	for name, types := range catalogs {
		for _, autoDemangle := range []bool{true, false} {
			f := sectionlessSwiftFile(autoDemangle)
			f.swiftClasses = buildSwiftClassIndex(types, autoDemangle, f.normalizeSwiftIdentifier)
			for _, lookup := range lookups {
				t.Run(fmt.Sprintf("%s/demangle=%t/%q", name, autoDemangle, lookup), func(t *testing.T) {
					want := linearSwiftFieldTypes(types, lookup, f.normalizeSwiftIdentifier)
					got, err := f.swiftFieldTypesForClass(lookup)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("got %v, want %v", got, want)
					}
				})
			}
		}
	}
}

func TestSwiftClassIndexFirstMatchWinsOnAliasCollision(t *testing.T) {
	first := swiftClassFixture("_TtC3Mod3Foo", "", map[string]string{"first": "Si"})
	second := swiftClassFixture("Foo", "Mod", map[string]string{"second": "SS"})
	f := sectionlessSwiftFile(true)
	normalize := f.normalizeSwiftIdentifier
	idx := buildSwiftClassIndex([]swift.Type{first, second}, true, normalize)

	for _, lookup := range []string{"Mod.Foo", "_TtC3Mod3Foo", "_OBJC_CLASS_$__TtC3Mod3Foo"} {
		fields, ok := idx.lookup(swiftClassLookupNames(lookup, normalize))
		if !ok || fields == nil || len(fields.Records) != 1 || fields.Records[0].Name != "first" {
			t.Fatalf("lookup %q selected %+v, want the first catalog entry", lookup, fields)
		}
	}
}

func TestSwiftClassIndexNormalizationMode(t *testing.T) {
	types := []swift.Type{swiftClassFixture("$s3Mod3FooC", "", map[string]string{"x": "Si"})}
	for _, tc := range []struct {
		autoDemangle bool
		want         bool
	}{{true, true}, {false, false}} {
		f := sectionlessSwiftFile(tc.autoDemangle)
		idx := buildSwiftClassIndex(types, tc.autoDemangle, f.normalizeSwiftIdentifier)
		_, ok := idx.lookup(swiftClassLookupNames("Mod.Foo", f.normalizeSwiftIdentifier))
		if ok != tc.want {
			t.Fatalf("autoDemangle=%t matched=%t, want %t", tc.autoDemangle, ok, tc.want)
		}
	}
}

func TestSwiftFieldTypesForClassReusesIndexUntilModeChanges(t *testing.T) {
	f := sectionlessSwiftFile(true)
	if _, err := f.swiftFieldTypesForClass("Mod.Foo"); !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("expected catalog error before an index exists, got %v", err)
	}
	if f.swiftClasses != nil {
		t.Fatal("a failed catalog parse must not be cached")
	}

	types := []swift.Type{swiftClassFixture("Foo", "Mod", map[string]string{"x": "Si"})}
	f.swiftClasses = buildSwiftClassIndex(types, true, f.normalizeSwiftIdentifier)
	for i := 0; i < 3; i++ {
		got, err := f.swiftFieldTypesForClass("Mod.Foo")
		if err != nil || got["x"] != "Si" {
			t.Fatalf("lookup %d = %v, %v; want the indexed fields without a rescan", i, got, err)
		}
	}
	if got, err := f.swiftFieldTypesForClass("Mod.Missing"); err != nil || got != nil {
		t.Fatalf("miss = %v, %v; want nil, nil", got, err)
	}

	f.SetSwiftAutoDemangle(false)
	if _, err := f.swiftFieldTypesForClass("Mod.Foo"); !errors.Is(err, ErrSwiftSectionError) {
		t.Fatalf("changing the normalization mode must rebuild the index, got %v", err)
	}
	f.SetSwiftAutoDemangle(true)
	if got, err := f.swiftFieldTypesForClass("Mod.Foo"); err != nil || got["x"] != "Si" {
		t.Fatalf("index for the restored mode = %v, %v", got, err)
	}
}

func TestSwiftFieldTypesForClassBuildsIndexFromFile(t *testing.T) {
	data, _ := swiftColocatedFixture(swift.CDKindClass, false, 0, 2, true)
	f, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.swiftFieldTypesForClass("Module.Before")
	if err != nil || got != nil {
		t.Fatalf("class without a field descriptor = %v, %v; want nil, nil", got, err)
	}
	if f.swiftClasses == nil {
		t.Fatal("expected the index to be built from the parsed catalog")
	}
	if _, ok := f.swiftClasses.byName["Module.Before"]; !ok {
		t.Fatalf("index names = %v, want Module.Before", f.swiftClasses.byName)
	}
	if f.swiftClasses.autoDemangle != f.SwiftAutoDemangle() {
		t.Fatal("index must record the normalization mode it was built with")
	}
}

func benchmarkSwiftClassCatalog(n int) []swift.Type {
	types := make([]swift.Type, 0, n)
	for i := 0; i < n; i++ {
		types = append(types, swiftClassFixture(fmt.Sprintf("Class%d", i), "Mod",
			map[string]string{"field": "Si"}))
	}
	return types
}

func BenchmarkSwiftFieldTypesForClassIndexed(b *testing.B) {
	for _, n := range []int{1000, 30000} {
		types := benchmarkSwiftClassCatalog(n)
		f := sectionlessSwiftFile(true)
		f.swiftClasses = buildSwiftClassIndex(types, true, f.normalizeSwiftIdentifier)
		lookup := fmt.Sprintf("Mod.Class%d", n-1)
		b.Run(fmt.Sprintf("classes=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if got, err := f.swiftFieldTypesForClass(lookup); err != nil || got["field"] != "Si" {
					b.Fatalf("lookup = %v, %v", got, err)
				}
			}
		})
	}
}

func BenchmarkSwiftFieldTypesForClassLinearScan(b *testing.B) {
	for _, n := range []int{1000, 30000} {
		types := benchmarkSwiftClassCatalog(n)
		f := sectionlessSwiftFile(true)
		lookup := fmt.Sprintf("Mod.Class%d", n-1)
		b.Run(fmt.Sprintf("classes=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if got := linearSwiftFieldTypes(types, lookup, f.normalizeSwiftIdentifier); got["field"] != "Si" {
					b.Fatalf("lookup = %v", got)
				}
			}
		})
	}
}
