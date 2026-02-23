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
