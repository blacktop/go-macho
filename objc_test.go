package macho

import (
	"errors"
	"testing"

	"github.com/blacktop/go-macho/types"
)

type objcTestSection struct {
	seg  string
	name string
}

type objcAPICall struct {
	name string
	run  func(*File) error
}

func callNoArg[T any](call func() (T, error)) error {
	_, err := call()
	return err
}

func runObjCAPICases(t *testing.T, f *File, cases []objcAPICall, validErr func(error) bool, failMsg string) {
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

func newObjCTestFile(defs ...objcTestSection) *File {
	sectionsBySegment := make(map[string][]string)
	var segmentOrder []string

	for _, def := range defs {
		if _, ok := sectionsBySegment[def.seg]; !ok {
			segmentOrder = append(segmentOrder, def.seg)
		}
		sectionsBySegment[def.seg] = append(sectionsBySegment[def.seg], def.name)
	}

	var sections []*types.Section
	var ls loads
	firstSect := uint32(0)

	for _, segName := range segmentOrder {
		segSections := sectionsBySegment[segName]
		ls = append(ls, &Segment{
			SegmentHeader: SegmentHeader{
				Name:      segName,
				Nsect:     uint32(len(segSections)),
				Firstsect: firstSect,
			},
		})
		for _, secName := range segSections {
			sections = append(sections, &types.Section{
				SectionHeader: types.SectionHeader{
					Seg:  segName,
					Name: secName,
				},
			})
		}
		firstSect += uint32(len(segSections))
	}

	return &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{
				Magic: types.Magic64,
				Type:  types.MH_EXECUTE,
			},
			Loads:    ls,
			Sections: sections,
		},
		objc:  make(map[uint64]any),
		swift: make(map[uint64]any),
	}
}

func callGetObjCMethodsAtZero(f *File) error {
	_, err := f.GetObjCMethods(0)
	return err
}

func callGetObjCIvarsAtZero(f *File) error {
	_, err := f.GetObjCIvars(0)
	return err
}

func callGetObjCPropertiesAtZero(f *File) error {
	_, err := f.GetObjCProperties(0)
	return err
}

func TestHasObjCDetectsLegacyAndModernMetadata(t *testing.T) {
	modern := newObjCTestFile(
		objcSection("__DATA_CONST", "__objc_imageinfo"),
	)
	if !modern.HasObjC() {
		t.Fatalf("expected modern ObjC metadata to be detected")
	}

	legacy := newObjCTestFile(
		objcSection("__OBJC", "__module_info"),
		objcSection("__OBJC", "__class"),
	)
	if !legacy.HasObjC() {
		t.Fatalf("expected legacy ObjC metadata to be detected")
	}

	none := newObjCTestFile()
	if none.HasObjC() {
		t.Fatalf("expected Mach-O without ObjC metadata to report false")
	}
}

func TestObjCAPIsRejectFragileRuntimeOnly(t *testing.T) {
	legacyOnly := newObjCTestFile(
		objcSection("__OBJC", "__module_info"),
		objcSection("__OBJC", "__class"),
	)

	cases := []objcAPICall{
		{name: "GetObjCClasses", run: func(f *File) error { return callNoArg(f.GetObjCClasses) }},
		{name: "GetObjCMethods", run: callGetObjCMethodsAtZero},
		{name: "GetObjCIvars", run: callGetObjCIvarsAtZero},
		{name: "GetObjCProperties", run: callGetObjCPropertiesAtZero},
	}

	runObjCAPICases(
		t,
		legacyOnly,
		cases,
		func(err error) bool { return errors.Is(err, ErrObjcFragileRuntimeUnsupported) },
		"expected ErrObjcFragileRuntimeUnsupported",
	)
}

func TestObjCAPIsAllowMixedRuntimeMetadata(t *testing.T) {
	mixed := newObjCTestFile(
		objcSection("__OBJC", "__module_info"),
		objcSection("__OBJC", "__class"),
		objcSection("__DATA", "__objc_imageinfo"),
	)

	cases := []objcAPICall{
		{name: "GetObjCClassNames", run: func(f *File) error { return callNoArg(f.GetObjCClassNames) }},
		{name: "GetObjCMethodNames", run: func(f *File) error { return callNoArg(f.GetObjCMethodNames) }},
		{name: "GetObjCClasses", run: func(f *File) error { return callNoArg(f.GetObjCClasses) }},
		{name: "GetObjCProtocols", run: func(f *File) error { return callNoArg(f.GetObjCProtocols) }},
	}

	runObjCAPICases(
		t,
		mixed,
		cases,
		func(err error) bool { return !errors.Is(err, ErrObjcFragileRuntimeUnsupported) },
		"expected mixed-runtime metadata to bypass fragile-runtime rejection",
	)
}

func TestLegacySwiftObjCClassName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{
			name:  "simple class",
			input: "_TtC4apsd28ClientIdentityMetricReporter",
			want:  "apsd.ClientIdentityMetricReporter",
			ok:    true,
		},
		{
			name:  "nested class",
			input: "_TtCC4apsd20ClientIdentityMetric13FailureMetric",
			want:  "apsd.ClientIdentityMetric.FailureMetric",
			ok:    true,
		},
		{
			name:  "not a legacy swift objc class name",
			input: "NSObject",
			want:  "",
			ok:    false,
		},
		{
			name:  "reject trailing garbage suffix",
			input: "_TtC4apsd28ClientIdentityMetricReporterXX",
			want:  "",
			ok:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := legacySwiftObjCClassName(tt.input)
			if ok != tt.ok {
				t.Fatalf("legacySwiftObjCClassName(%q) ok=%v, want %v", tt.input, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("legacySwiftObjCClassName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSwiftClassLookupNames(t *testing.T) {
	lookup := swiftClassLookupNames("_OBJC_CLASS_$_TtCC4apsd20ClientIdentityMetric13FailureMetric", nil)

	if _, ok := lookup["_OBJC_CLASS_$_TtCC4apsd20ClientIdentityMetric13FailureMetric"]; !ok {
		t.Fatalf("expected lookup to contain original objc class symbol")
	}
	if _, ok := lookup["_TtCC4apsd20ClientIdentityMetric13FailureMetric"]; !ok {
		t.Fatalf("expected lookup to contain objc class symbol without _OBJC_CLASS_$_ prefix")
	}
	if _, ok := lookup["apsd.ClientIdentityMetric.FailureMetric"]; !ok {
		t.Fatalf("expected lookup to contain demangled legacy swift class name")
	}
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
			got := normalizeSwiftIvarTypeEncoding(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeSwiftIvarTypeEncoding(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
