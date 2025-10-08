package fixupchains

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestLookupFunctionality(t *testing.T) {
	tests := []struct {
		name          string
		setupFixups   func() *DyldChainedFixups
		targetOffset  uint64
		wantFound     bool
		wantAuth      bool
		wantDiversity uint64
	}{
		{
			name: "lookup auth rebase by target",
			setupFixups: func() *DyldChainedFixups {
				dcf := &DyldChainedFixups{
					fixups: make(map[uint64]Fixup),
					Starts: []DyldChainedStarts{
						{
							DyldChainedStartsInSegment: DyldChainedStartsInSegment{
								PointerFormat: DYLD_CHAINED_PTR_ARM64E,
							},
							Fixups: []Fixup{},
						},
					},
				}

				// Create an auth rebase fixup
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: 0x1234567890ABCDEF, // Example pointer with diversity
					Fixup:   0x1000,
				}

				// Add to both places
				dcf.Starts[0].Fixups = append(dcf.Starts[0].Fixups, authRebase)
				dcf.fixups[authRebase.Target()] = authRebase

				return dcf
			},
			targetOffset:  types.ExtractBits(0x1234567890ABCDEF, 0, 32), // Target from the pointer
			wantFound:     true,
			wantAuth:      true,
			wantDiversity: types.ExtractBits(0x1234567890ABCDEF, 32, 16), // Diversity from the pointer
		},
		{
			name: "lookup regular rebase by target",
			setupFixups: func() *DyldChainedFixups {
				dcf := &DyldChainedFixups{
					fixups: make(map[uint64]Fixup),
					Starts: []DyldChainedStarts{
						{
							DyldChainedStartsInSegment: DyldChainedStartsInSegment{
								PointerFormat: DYLD_CHAINED_PTR_64,
							},
							Fixups: []Fixup{},
						},
					},
				}

				// Create a regular rebase fixup
				rebase := DyldChainedPtr64Rebase{
					Pointer: 0x0000000100000000,
					Fixup:   0x2000,
				}

				// Add to both places
				dcf.Starts[0].Fixups = append(dcf.Starts[0].Fixups, rebase)
				dcf.fixups[rebase.Target()] = rebase

				return dcf
			},
			targetOffset:  types.ExtractBits(0x0000000100000000, 0, 36), // Target from the pointer
			wantFound:     true,
			wantAuth:      false,
			wantDiversity: 0,
		},
		{
			name: "lookup non-existent target",
			setupFixups: func() *DyldChainedFixups {
				return &DyldChainedFixups{
					fixups: make(map[uint64]Fixup),
					Starts: []DyldChainedStarts{},
				}
			},
			targetOffset:  0x9999,
			wantFound:     false,
			wantAuth:      false,
			wantDiversity: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcf := tt.setupFixups()

			// Test the original Lookup function
			fixup, found := dcf.Lookup(tt.targetOffset)
			if found != tt.wantFound {
				t.Errorf("Lookup() found = %v, want %v", found, tt.wantFound)
				return
			}

			if !found {
				return
			}

			// Test LookupByTarget
			fixups := dcf.LookupByTarget(tt.targetOffset)
			if tt.wantFound && len(fixups) == 0 {
				t.Error("LookupByTarget() returned no fixups when expected")
				return
			}

			// Test GetAuthRebase for auth fixups
			if tt.wantAuth {
				auth, ok := dcf.GetAuthRebase(tt.targetOffset)
				if !ok {
					t.Error("GetAuthRebase() failed to find auth fixup")
					return
				}

				if diversity := auth.Diversity(); diversity != tt.wantDiversity {
					t.Errorf("Diversity() = %v, want %v", diversity, tt.wantDiversity)
				}
			}

			// Verify the fixup is the correct type
			if tt.wantAuth {
				if _, ok := fixup.(Auth); !ok {
					t.Errorf("Expected Auth fixup, got %T", fixup)
				}
			} else {
				if _, ok := fixup.(Rebase); !ok {
					t.Errorf("Expected Rebase fixup, got %T", fixup)
				}
			}
		})
	}
}

func TestLookupByOffset(t *testing.T) {
	dcf := &DyldChainedFixups{
		Starts: []DyldChainedStarts{
			{
				Fixups: []Fixup{
					DyldChainedPtrArm64eRebase{
						Pointer: 0x1111111111111111,
						Fixup:   0x1000,
					},
					DyldChainedPtrArm64eAuthRebase{
						Pointer: 0x2222222222222222,
						Fixup:   0x2000,
					},
					DyldChainedPtrArm64eBind{
						Pointer: 0x3333333333333333,
						Fixup:   0x3000,
						Import:  "symbol",
					},
				},
			},
		},
	}

	tests := []struct {
		offset    uint64
		wantFound bool
		wantType  string
	}{
		{0x1000, true, "rebase"},
		{0x2000, true, "auth-rebase"},
		{0x3000, true, "bind"},
		{0x4000, false, ""},
	}

	for _, tt := range tests {
		fixup, found := dcf.LookupByOffset(tt.offset)
		if found != tt.wantFound {
			t.Errorf("LookupByOffset(0x%x) found = %v, want %v", tt.offset, found, tt.wantFound)
			continue
		}

		if found {
			var kind string
			switch fixup.(type) {
			case *DyldChainedPtrArm64eRebase, DyldChainedPtrArm64eRebase:
				kind = "rebase"
			case *DyldChainedPtrArm64eAuthRebase, DyldChainedPtrArm64eAuthRebase:
				kind = "auth-rebase"
			case *DyldChainedPtrArm64eBind, DyldChainedPtrArm64eBind:
				kind = "bind"
			default:
				kind = "unknown"
			}
			if kind != tt.wantType {
				t.Errorf("LookupByOffset(0x%x) returned %s, want %s", tt.offset, kind, tt.wantType)
			}
		}
	}
}

// mockChainedFixups creates a basic mock DyldChainedFixups for testing GetFixupAtOffset
func mockChainedFixups() *DyldChainedFixups {
	// Create minimal mock data for testing
	dcf := &DyldChainedFixups{
		DyldChainedFixupsHeader: DyldChainedFixupsHeader{
			FixupsVersion: 0,
			StartsOffset:  32,
			ImportsOffset: 100,
			SymbolsOffset: 200,
			ImportsCount:  2,
			ImportsFormat: DC_IMPORT,
			SymbolsFormat: DC_SFORMAT_UNCOMPRESSED,
		},
		PointerFormat: DYLD_CHAINED_PTR_64,
		Starts: []DyldChainedStarts{
			{
				DyldChainedStartsInSegment: DyldChainedStartsInSegment{
					Size:            40,
					PageSize:        0x4000, // 16KB pages
					PointerFormat:   DYLD_CHAINED_PTR_64,
					SegmentOffset:   0x10000, // Start at 64KB
					MaxValidPointer: 0xFFFFFF,
					PageCount:       4,
				},
				PageStarts: []DCPtrStart{
					0x100,                       // Page 0: fixup at offset 0x100
					DYLD_CHAINED_PTR_START_NONE, // Page 1: no fixups
					0x200,                       // Page 2: fixup at offset 0x200
					DYLD_CHAINED_PTR_START_NONE, // Page 3: no fixups
				},
			},
		},
		Imports: []DcfImport{
			{Name: "_printf", Import: DyldChainedImport(0x123)},
			{Name: "_malloc", Import: DyldChainedImport(0x456)},
		},
		fixups:         make(map[uint64]Fixup),
		metadataParsed: true,
		importsParsed:  true,
		chainsParsed:   false,
	}

	// Create mock reader with some data
	data := make([]byte, 1024)
	dcf.r = bytes.NewReader(data)
	// We'll set sr to nil for this simplified test - the actual implementation
	// would need a proper MachoReader implementation
	dcf.bo = binary.LittleEndian

	return dcf
}

func TestGetFixupAtOffset(t *testing.T) {
	tests := []struct {
		name        string
		offset      uint64
		expectError bool
		errorType   error
	}{
		{
			name:        "offset with no fixup page",
			offset:      0x10000 + 0x4000 + 0x100, // Page 1 + some offset (page has no fixups)
			expectError: true,
			errorType:   ErrNoFixupAtOffset,
		},
		{
			name:        "offset not aligned to pointer size",
			offset:      0x10000 + 0x101, // Page 0 + misaligned offset
			expectError: true,
			errorType:   ErrNoFixupAtOffset,
		},
		{
			name:        "offset not aligned to stride",
			offset:      0x10000 + 0x102, // Page 0 + offset not aligned to 4-byte stride
			expectError: true,
			errorType:   ErrNoFixupAtOffset,
		},
		{
			name:        "offset outside segment range",
			offset:      0x8000, // Before segment start
			expectError: true,
		},
	}

	dcf := mockChainedFixups()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixup, err := dcf.GetFixupAtOffset(tt.offset)

			if tt.expectError {
				if err == nil {
					t.Errorf("GetFixupAtOffset() expected error but got none")
					return
				}
				if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("GetFixupAtOffset() error = %v, want %v", err, tt.errorType)
				}
				if fixup != nil {
					t.Errorf("GetFixupAtOffset() expected nil fixup but got %v", fixup)
				}
			} else {
				if err != nil {
					t.Errorf("GetFixupAtOffset() unexpected error = %v", err)
					return
				}
				if fixup == nil {
					t.Errorf("GetFixupAtOffset() expected fixup but got nil")
				}
			}
		})
	}
}
