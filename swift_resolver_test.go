package macho

import (
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	swiftdemangle "github.com/blacktop/go-macho/internal/swiftdemangle"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/swift"
)

// TestMachOResolver_ContextDescToNode tests the conversion of context descriptors to demangler nodes.
func TestMachOResolver_ContextDescToNode(t *testing.T) {
	tests := []struct {
		name    string
		ctx     *swift.TargetModuleContext
		want    swiftdemangle.NodeKind
		wantErr bool
	}{
		{
			name: "module context",
			ctx: &swift.TargetModuleContext{
				Name: "Swift",
				TargetModuleContextDescriptor: swift.TargetModuleContextDescriptor{
					TargetContextDescriptor: swift.TargetContextDescriptor{
						Flags: swift.ContextDescriptorFlags(uint32(swift.CDKindModule)),
					},
				},
			},
			want:    swiftdemangle.KindModule,
			wantErr: false,
		},
		{
			name: "class context",
			ctx: &swift.TargetModuleContext{
				Name:   "MyClass",
				Parent: "MyModule",
				TargetModuleContextDescriptor: swift.TargetModuleContextDescriptor{
					TargetContextDescriptor: swift.TargetContextDescriptor{
						Flags: swift.ContextDescriptorFlags(uint32(swift.CDKindClass)),
					},
				},
			},
			want:    swiftdemangle.KindClass,
			wantErr: false,
		},
		{
			name: "struct context",
			ctx: &swift.TargetModuleContext{
				Name:   "MyStruct",
				Parent: "MyModule",
				TargetModuleContextDescriptor: swift.TargetModuleContextDescriptor{
					TargetContextDescriptor: swift.TargetContextDescriptor{
						Flags: swift.ContextDescriptorFlags(uint32(swift.CDKindStruct)),
					},
				},
			},
			want:    swiftdemangle.KindStructure,
			wantErr: false,
		},
		{
			name: "enum context",
			ctx: &swift.TargetModuleContext{
				Name:   "MyEnum",
				Parent: "MyModule",
				TargetModuleContextDescriptor: swift.TargetModuleContextDescriptor{
					TargetContextDescriptor: swift.TargetContextDescriptor{
						Flags: swift.ContextDescriptorFlags(uint32(swift.CDKindEnum)),
					},
				},
			},
			want:    swiftdemangle.KindEnum,
			wantErr: false,
		},
		{
			name: "protocol context",
			ctx: &swift.TargetModuleContext{
				Name:   "MyProtocol",
				Parent: "Swift",
				TargetModuleContextDescriptor: swift.TargetModuleContextDescriptor{
					TargetContextDescriptor: swift.TargetContextDescriptor{
						Flags: swift.ContextDescriptorFlags(uint32(swift.CDKindProtocol)),
					},
				},
			},
			want:    swiftdemangle.KindProtocol,
			wantErr: false,
		},
		{
			name: "nested context",
			ctx: &swift.TargetModuleContext{
				Name:   "Inner",
				Parent: "MyModule.Outer",
				TargetModuleContextDescriptor: swift.TargetModuleContextDescriptor{
					TargetContextDescriptor: swift.TargetContextDescriptor{
						Flags: swift.ContextDescriptorFlags(uint32(swift.CDKindStruct)),
					},
				},
			},
			want:    swiftdemangle.KindStructure,
			wantErr: false,
		},
		{
			name:    "nil context",
			ctx:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &machOResolver{}
			node, err := resolver.contextDescToNode(tt.ctx)

			if tt.wantErr {
				if err == nil {
					t.Errorf("contextDescToNode() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("contextDescToNode() unexpected error: %v", err)
				return
			}

			if node == nil {
				t.Error("contextDescToNode() returned nil node")
				return
			}

			if node.Kind != tt.want {
				t.Errorf("contextDescToNode() kind = %v, want %v", node.Kind, tt.want)
			}

			if node.Text != tt.ctx.Name {
				t.Errorf("contextDescToNode() text = %v, want %v", node.Text, tt.ctx.Name)
			}

			// Verify parent context is properly represented
			if tt.ctx != nil && tt.ctx.Parent != "" {
				if len(node.Children) == 0 {
					t.Errorf("contextDescToNode() expected parent nodes but got none")
				}
			}
		})
	}
}

// TestMachOResolver_UnsupportedControlByte tests handling of unsupported symbolic reference types.
func TestMachOResolver_UnsupportedControlByte(t *testing.T) {
	resolver := &machOResolver{
		f:        &File{}, // Mock file - won't be used in this test
		baseAddr: 0x1000,
	}

	// Test an unsupported control byte (use a value outside the current table)
	_, err := resolver.ResolveType(0x40, nil, 0)
	if err == nil {
		t.Error("ResolveType() expected error for unsupported control byte 0x40")
	}

	if err != nil && err.Error() != "unsupported symbolic reference control byte: 0x40" {
		t.Errorf("ResolveType() wrong error message: %v", err)
	}
}

type fakeReader struct {
	data []byte
	pos  int64
	vma  *types.VMAddrConverter
}

func newFakeReader(data []byte, vma *types.VMAddrConverter) *fakeReader {
	return &fakeReader{data: data, vma: vma}
}

func (r *fakeReader) Read(p []byte) (int, error) {
	if r.pos >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += int64(n)
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func newTestResolver(data []byte) (*machOResolver, *File) {
	vma := &types.VMAddrConverter{
		Converter:    func(addr uint64) uint64 { return addr },
		VMAddr2Offet: func(addr uint64) (uint64, error) { return addr, nil },
		Offet2VMAddr: func(off uint64) (uint64, error) { return off, nil },
	}

	reader := newFakeReader(data, vma)

	f := &File{}
	f.vma = vma
	f.cr = reader
	f.sr = reader
	f.ByteOrder = binary.LittleEndian

	resolver := &machOResolver{
		f:        f,
		baseAddr: 0,
	}

	return resolver, f
}

func TestMachOResolver_SymbolicReferenceKinds(t *testing.T) {
	type expectation struct {
		name       string
		control    byte
		payload    []byte
		prepare    func(data []byte)
		wantKind   swiftdemangle.NodeKind
		wantText   string
		childCheck func(t *testing.T, node *swiftdemangle.Node)
	}

	directOffset := func(target uint64) []byte {
		offset := int32(target - 1) // refIndex=0, base=0
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(offset))
		return buf
	}

	absolutePointer := func(target uint64) []byte {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, target)
		return buf
	}

	tests := []expectation{
		{
			name:    "DirectProtocolConformance",
			control: 0x03,
			payload: directOffset(0x40),
			prepare: func(data []byte) {
				// descriptor bytes already zeroed
			},
			wantKind: swiftdemangle.KindProtocolConformanceDescriptor,
		},
		{
			name:    "IndirectProtocolConformance",
			control: 0x04,
			prepare: func(data []byte) {
				// pointer at 0x60 -> descriptor at 0x80
				binary.LittleEndian.PutUint64(data[0x60:], 0x80)
			},
			payload:  directOffset(0x60),
			wantKind: swiftdemangle.KindProtocolConformanceDescriptor,
		},
		{
			name:     "AssociatedConformanceDescriptor",
			control:  0x05,
			payload:  directOffset(0x90),
			wantKind: swiftdemangle.KindAssociatedConformanceDescriptor,
			wantText: "associated conformance descriptor at 0x90",
		},
		{
			name:    "AssociatedConformanceDescriptorIndirect",
			control: 0x06,
			prepare: func(data []byte) {
				binary.LittleEndian.PutUint64(data[0xA0:], 0x120)
			},
			payload:  directOffset(0xA0),
			wantKind: swiftdemangle.KindAssociatedConformanceDescriptor,
			wantText: "associated conformance descriptor at 0x120",
		},
		{
			name:     "AssociatedConformanceAccess",
			control:  0x07,
			payload:  directOffset(0x140),
			wantKind: swiftdemangle.KindDefaultAssociatedConformanceAccessor,
			childCheck: func(t *testing.T, node *swiftdemangle.Node) {
				if len(node.Children) != 1 {
					t.Fatalf("expected one child, got %d", len(node.Children))
				}
				if node.Children[0].Text != "0x140" {
					t.Fatalf("unexpected child text %q", node.Children[0].Text)
				}
			},
		},
		{
			name:     "AssociatedConformanceAccessIndirect",
			control:  0x08,
			payload:  directOffset(0x150),
			wantKind: swiftdemangle.KindDefaultAssociatedConformanceAccessor,
		},
		{
			name:     "AccessorFunctionReference",
			control:  0x09,
			payload:  directOffset(0x160),
			wantKind: swiftdemangle.KindAccessorFunctionReference,
			wantText: "0x160",
		},
		{
			name:     "UniqueExistentialShape",
			control:  0x0a,
			payload:  directOffset(0x170),
			wantKind: swiftdemangle.KindUniqueExtendedExistentialTypeShapeSymbolicReference,
			wantText: "0x170",
		},
		{
			name:     "NonUniqueExistentialShape",
			control:  0x0b,
			payload:  directOffset(0x180),
			wantKind: swiftdemangle.KindNonUniqueExtendedExistentialTypeShapeSymbolicReference,
			wantText: "0x180",
		},
		{
			name:    "ObjectiveCProtocol",
			control: 0x0c,
			prepare: func(data []byte) {
				// relative pointer from addr+4 to mangled string at 0x1c0
				binary.LittleEndian.PutUint32(data[0x1b4:], uint32(0x1c0-0x1b4))
				copy(data[0x1c0:], []byte("Si\x00"))
			},
			payload:  directOffset(0x1b0),
			wantKind: swiftdemangle.KindObjectiveCProtocolSymbolicReference,
			childCheck: func(t *testing.T, node *swiftdemangle.Node) {
				if node.Text == "" {
					t.Fatalf("expected Objective-C protocol text")
				}
			},
		},
		{
			name:     "AbsoluteAssociatedConformanceAccess",
			control:  0x1e,
			payload:  absolutePointer(0x1d0),
			wantKind: swiftdemangle.KindDefaultAssociatedConformanceAccessor,
			wantText: "",
			childCheck: func(t *testing.T, node *swiftdemangle.Node) {
				if len(node.Children) != 1 || node.Children[0].Text != "0x1d0" {
					t.Fatalf("unexpected child for absolute access node: %+v", node.Children)
				}
			},
		},
		{
			name:     "AbsoluteAssociatedConformanceAccessAlt",
			control:  0x1f,
			payload:  absolutePointer(0x1e0),
			wantKind: swiftdemangle.KindDefaultAssociatedConformanceAccessor,
			childCheck: func(t *testing.T, node *swiftdemangle.Node) {
				if len(node.Children) != 1 || node.Children[0].Text != "0x1e0" {
					t.Fatalf("unexpected child for absolute alt node: %+v", node.Children)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 0x400)
			if tt.prepare != nil {
				tt.prepare(data)
			}

			resolver, _ := newTestResolver(data)

			payload := tt.payload
			if payload == nil {
				// build indirect payload that relies on mutate data map if needed
				payload = tt.payload
			}

			node, err := resolver.ResolveType(tt.control, payload, 0)
			if err != nil {
				t.Fatalf("ResolveType failed: %v", err)
			}
			if node == nil {
				t.Fatal("ResolveType returned nil node")
			}
			if node.Kind != tt.wantKind {
				t.Fatalf("kind mismatch: got %s want %s", node.Kind, tt.wantKind)
			}
			if tt.wantText != "" && node.Text != tt.wantText {
				t.Fatalf("text mismatch: got %q want %q", node.Text, tt.wantText)
			}
			if tt.childCheck != nil {
				tt.childCheck(t, node)
			}
		})
	}
}

func (r *fakeReader) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = r.pos + offset
	case io.SeekEnd:
		newPos = int64(len(r.data)) + offset
	default:
		return 0, fmt.Errorf("invalid whence %d", whence)
	}
	if newPos < 0 || newPos > int64(len(r.data)) {
		return 0, fmt.Errorf("invalid seek position %d", newPos)
	}
	r.pos = newPos
	return r.pos, nil
}

func (r *fakeReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *fakeReader) SeekToAddr(addr uint64) error {
	off, err := r.vma.VMAddr2Offet(addr)
	if err != nil {
		return err
	}
	_, err = r.Seek(int64(off), io.SeekStart)
	return err
}

func (r *fakeReader) ReadAtAddr(p []byte, addr uint64) (int, error) {
	off, err := r.vma.VMAddr2Offet(addr)
	if err != nil {
		return 0, err
	}
	return r.ReadAt(p, int64(off))
}
