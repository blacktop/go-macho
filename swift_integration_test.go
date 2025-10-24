package macho

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types/objc"
	"github.com/blacktop/go-macho/types/swift"
)

func TestSwiftDemanglerIntegration(t *testing.T) {
	swiftc, err := exec.LookPath("swiftc")
	if err != nil {
		t.Skip("swiftc not available")
	}

	fixture := filepath.Join("internal", "testdata", "test.swift")
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "libDemangleFixtures.dylib")

	cmd := exec.Command(swiftc, "-module-name", "DemangleFixtures", "-emit-library", "-o", outPath, fixture)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("swiftc failed: %v\n%s", err, stderr.String())
	}

	f, err := Open(outPath)
	if err != nil {
		t.Fatalf("failed to open compiled swift fixture: %v", err)
	}
	defer f.Close()

	fields, err := f.GetSwiftFields()
	if err != nil {
		t.Fatalf("GetSwiftFields failed: %v", err)
	}

	findField := func(name string) *swift.Field {
		for i := range fields {
			if fields[i].Type == name {
				return &fields[i]
			}
		}
		return nil
	}

	outer := findField("DemangleFixtures.Outer")
	if outer == nil {
		t.Fatalf("failed to locate field descriptor for DemangleFixtures.Outer")
	}
	gotOuter := map[string]string{}
	for _, rec := range outer.Records {
		gotOuter[rec.Name] = rec.MangledType
	}
	if gotOuter["inner"] != "DemangleFixtures.Outer.Inner" {
		t.Fatalf("outer.inner type mismatch: got %q", gotOuter["inner"])
	}
	if gotOuter["tuple"] != "(Swift.Int, Swift.String)" {
		t.Fatalf("outer.tuple type mismatch: got %q", gotOuter["tuple"])
	}
	wantOptional := "DemangleFixtures.Outer.Inner?"
	gotOptional := strings.ReplaceAll(gotOuter["maybe"], " ", "")
	if gotOptional != wantOptional {
		t.Fatalf("outer.maybe optional type mismatch: got %q (normalized %q)", gotOuter["maybe"], gotOptional)
	}

	inner := findField("DemangleFixtures.Outer.Inner")
	if inner == nil {
		t.Fatalf("failed to locate field descriptor for DemangleFixtures.Outer.Inner")
	}
	if len(inner.Records) != 1 || inner.Records[0].MangledType != "Swift.Int" {
		t.Fatalf("inner.value type mismatch: %+v", inner.Records)
	}

	demoClass := findField("DemangleFixtures.DemoClass")
	if demoClass == nil {
		t.Fatalf("failed to locate field descriptor for DemangleFixtures.DemoClass")
	}
	if len(demoClass.Records) != 1 || demoClass.Records[0].MangledType != "[Swift.Int]" {
		t.Fatalf("DemoClass.numbers type mismatch: %+v", demoClass.Records)
	}

	counter := findField("DemangleFixtures.Counter")
	if counter == nil {
		t.Fatalf("failed to locate field descriptor for DemangleFixtures.Counter")
	}
	counterTypes := map[string]string{}
	for _, rec := range counter.Records {
		counterTypes[rec.Name] = rec.MangledType
	}
	if counterTypes["value"] != "Swift.Int" {
		t.Fatalf("Counter.value type mismatch: %q", counterTypes["value"])
	}
	if counterTypes["$defaultActor"] != "Builtin.DefaultActorStorage" {
		t.Fatalf("Counter default actor storage mismatch: %q", counterTypes["$defaultActor"])
	}

	existential := findField("DemangleFixtures.ExistentialHolder")
	if existential == nil {
		t.Fatalf("failed to locate field descriptor for DemangleFixtures.ExistentialHolder")
	}
	if len(existential.Records) != 1 || existential.Records[0].MangledType != "DemangleFixtures.DemoProtocol" {
		t.Fatalf("ExistentialHolder.value type mismatch: %+v", existential.Records)
	}

	genericHolder := findField("DemangleFixtures.GenericHolder")
	if genericHolder == nil {
		t.Fatalf("failed to locate field descriptor for DemangleFixtures.GenericHolder")
	}
	if len(genericHolder.Records) != 1 || genericHolder.Records[0].MangledType != "A" {
		t.Fatalf("GenericHolder.value type mismatch: %+v", genericHolder.Records)
	}

	payload := findField("DemangleFixtures.Payload")
	if payload == nil {
		t.Fatalf("failed to locate field descriptor for DemangleFixtures.Payload")
	}
	payloadTypes := map[string]string{}
	for _, rec := range payload.Records {
		payloadTypes[rec.Name] = rec.MangledType
	}
	if payloadTypes["simple"] != "DemangleFixtures.Outer.Inner" {
		t.Fatalf("Payload.simple type mismatch: %q", payloadTypes["simple"])
	}
	if payloadTypes["complex"] != "(Swift.Int, Swift.String)?" {
		t.Fatalf("Payload.complex type mismatch: %q", payloadTypes["complex"])
	}

	funcs, err := f.GetSwiftAccessibleFunctions()
	if err != nil {
		if !errors.Is(err, ErrSwiftSectionError) {
			t.Fatalf("GetSwiftAccessibleFunctions failed: %v", err)
		}
		return
	}
	foundCombine := false
	for _, fn := range funcs {
		if strings.Contains(fn.Name, "combine") {
			foundCombine = true
			wantTy := "(DemangleFixtures.Outer.Inner, DemangleFixtures.Outer.Inner) async throws -> DemangleFixtures.Outer.Inner"
			normalized := strings.Join(strings.Fields(fn.FunctionType), " ")
			if normalized != wantTy {
				t.Fatalf("combine function type mismatch: got %q", fn.FunctionType)
			}
		}
	}
	if !foundCombine {
		t.Fatalf("combine accessible function not found")
	}

	classes, err := f.GetObjCClasses()
	if err != nil {
		t.Fatalf("GetObjCClasses failed: %v", err)
	}
	var bridge *objc.Class
	for idx := range classes {
		if classes[idx].Name == "DemangleFixtures.ObjCBridgeClass" {
			bridge = &classes[idx]
			break
		}
	}
	if bridge == nil {
		t.Fatalf("ObjC bridge class not found; available classes: %d", len(classes))
	}
	if bridge.SuperClass != "NSObject" {
		t.Fatalf("ObjC bridge superclass mismatch: got %q", bridge.SuperClass)
	}
	foundSelector := false
	for _, method := range bridge.InstanceMethods {
		if method.Name == "updateLabelWith:" {
			foundSelector = true
			break
		}
	}
	if !foundSelector {
		t.Fatalf("ObjC bridge class missing updateLabelWith: selector; methods: %+v", bridge.InstanceMethods)
	}
}
