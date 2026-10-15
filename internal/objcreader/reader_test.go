package objcreader_test

import (
	"errors"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/internal/objcreader"
)

type objcAPICall struct {
	name string
	run  func(*macho.File) error
}

func callNoArg[T any](call func() (T, error)) error {
	_, err := call()
	return err
}

func runObjCAPICases(
	t *testing.T, f *macho.File, cases []objcAPICall,
	validErr func(error) bool, failMsg string,
) {
	t.Helper()

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(f)
			if !validErr(err) {
				t.Fatalf("%s, got: %v", failMsg, err)
			}
		})
	}
}

func objcSection(seg, name string) objcTestSection {
	return objcTestSection{seg: seg, name: name}
}

func callGetObjCMethodsAtZero(f *macho.File) error {
	_, err := f.GetObjCMethods(0)
	return err
}

func callGetObjCIvarsAtZero(f *macho.File) error {
	_, err := f.GetObjCIvars(0)
	return err
}

func callGetObjCPropertiesAtZero(f *macho.File) error {
	_, err := f.GetObjCProperties(0)
	return err
}

func TestHasObjCDetectsLegacyAndModernMetadata(t *testing.T) {
	modern := newObjCTestFile(t, nil,
		objcSection("__DATA_CONST", "__objc_imageinfo"),
	)
	if !modern.HasObjC() {
		t.Fatalf("expected modern ObjC metadata to be detected")
	}

	legacy := newObjCTestFile(t, nil,
		objcSection("__OBJC", "__module_info"),
		objcSection("__OBJC", "__class"),
	)
	if !legacy.HasObjC() {
		t.Fatalf("expected legacy ObjC metadata to be detected")
	}

	none := newObjCTestFile(t, nil)
	if none.HasObjC() {
		t.Fatalf("expected Mach-O without ObjC metadata to report false")
	}
}

func TestObjCAPIsRejectFragileRuntimeOnly(t *testing.T) {
	legacyOnly := newObjCTestFile(t, nil,
		objcSection("__OBJC", "__module_info"),
		objcSection("__OBJC", "__class"),
	)

	cases := []objcAPICall{
		{name: "GetObjCClasses", run: func(f *macho.File) error { return callNoArg(f.GetObjCClasses) }},
		{name: "GetObjCMethods", run: callGetObjCMethodsAtZero},
		{name: "GetObjCIvars", run: callGetObjCIvarsAtZero},
		{name: "GetObjCProperties", run: callGetObjCPropertiesAtZero},
	}

	runObjCAPICases(
		t,
		legacyOnly,
		cases,
		func(err error) bool { return errors.Is(err, macho.ErrObjcFragileRuntimeUnsupported) },
		"expected macho.ErrObjcFragileRuntimeUnsupported",
	)
}

func TestObjCAPIsAllowMixedRuntimeMetadata(t *testing.T) {
	mixed := newObjCTestFile(t, nil,
		objcSection("__OBJC", "__module_info"),
		objcSection("__OBJC", "__class"),
		objcSection("__DATA", "__objc_imageinfo"),
	)

	cases := []objcAPICall{
		{name: "GetObjCClassNames", run: func(f *macho.File) error {
			return callNoArg(f.GetObjCClassNames)
		}},
		{name: "GetObjCMethodNames", run: func(f *macho.File) error {
			return callNoArg(f.GetObjCMethodNames)
		}},
		{name: "GetObjCClasses", run: func(f *macho.File) error { return callNoArg(f.GetObjCClasses) }},
		{name: "GetObjCProtocols", run: func(f *macho.File) error {
			return callNoArg(f.GetObjCProtocols)
		}},
	}

	runObjCAPICases(
		t,
		mixed,
		cases,
		func(err error) bool { return !errors.Is(err, macho.ErrObjcFragileRuntimeUnsupported) },
		"expected mixed-runtime metadata to bypass fragile-runtime rejection",
	)
}

func TestNormalizeSwiftIvarTypeEncoding(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "method signature returns object",
			input: "@40@0:8Q16Q24B32B36",
			want:  "@",
		},
		{
			name:  "method signature returns class object",
			input: "@\"NSString\"24@0:8q16",
			want:  "@\"NSString\"",
		},
		{
			name:  "already ivar encoding",
			input: "Q",
			want:  "Q",
		},
		{
			name:  "swift mangled type token",
			input: "Sb",
			want:  "Sb",
		},
		{
			name:  "non method encoding with colon absent",
			input: "{CGRect={CGPoint=dd}{CGSize=dd}}",
			want:  "{CGRect={CGPoint=dd}{CGSize=dd}}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := objcreader.NormalizeSwiftIvarTypeEncoding(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeSwiftIvarTypeEncoding(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
