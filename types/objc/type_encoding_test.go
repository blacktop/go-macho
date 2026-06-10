package objc

import "testing"

func Test_decodeType(t *testing.T) {
	type args struct {
		encType string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test all",
			args: args{
				encType: "^{OutterStruct=(InnerUnion=q{InnerStruct=ii})b1b2b10b1q[2^v]^![4,8c]AQ}",
			},
			want: "struct OutterStruct { union InnerUnion { long long x0; struct InnerStruct { int x0; int x1; } x1; } x0; unsigned int x1:1; unsigned int x2:2; unsigned int x3:10; unsigned int x4:1; long long x5; void *x6[2]; signed char *x7 __attribute__((aligned(8), vector_size(4))); _Atomic unsigned long long x8; } *",
		},
		{
			name: "Test array 0",
			args: args{
				encType: "[2^v]",
			},
			want: "void *x[2]",
		},
		{
			name: "Test array 1",
			args: args{
				encType: "[20{IDSGlobalLinkAttribute=\"type\"S\"len\"S\"value\"(?=\"ss\"{sockaddr_storage=\"ss_len\"C\"ss_family\"C\"__ss_pad1\"[6c]\"__ss_align\"q\"__ss_pad2\"[112c]}\"u16\"S\"u32\"I\"u64\"Q\"binaryData\"{IDSGLAttrBinaryData_=\"len\"i\"data\"[1024C]})}]",
			},
			want: "struct IDSGlobalLinkAttribute { unsigned short type; unsigned short len; union { struct sockaddr_storage { unsigned char ss_len; unsigned char ss_family; signed char __ss_pad1[6]; long long __ss_align; signed char __ss_pad2[112]; } ss; unsigned short u16; unsigned int u32; unsigned long long u64; struct IDSGLAttrBinaryData_ { int len; unsigned char data[1024]; } binaryData; } value; } x[20]",
		},
		{
			name: "Test bitfield",
			args: args{
				encType: "b13",
			},
			want: "unsigned int x:13",
		},
		{
			name: "Test bitfield 128",
			args: args{
				encType: "b128",
			},
			want: "unsigned __int128 x:128",
		},
		{
			name: "Test bitfield 200",
			args: args{
				encType: "b200",
			},
			want: "unsigned __int128 x:128 /* unsupported bitfield width 200 */",
		},
		{
			name: "Test struct 0",
			args: args{
				encType: "{test=@*i}",
			},
			want: "struct test { id x0; char *x1; int x2; }",
		},
		{
			name: "Test struct 1",
			args: args{
				encType: "{?=i[3f]b3b2c}",
			},
			want: "struct { int x0; float x1[3]; unsigned int x2:3; unsigned int x3:2; signed char x4; }",
		},
		{
			name: "Test struct bitfield widths",
			args: args{
				encType: "{?=ib33b64b128}",
			},
			want: "struct { int x0; unsigned long long x1:33; unsigned long long x2:64; unsigned __int128 x3:128; }",
		},
		{
			name: "Test struct bitfield width overflow",
			args: args{
				encType: "{?=b200}",
			},
			want: "struct { unsigned __int128 x0:128 /* unsupported bitfield width 200 */; }",
		},
		{
			name: "Test struct 3",
			args: args{
				encType: "{__xar_t=}",
			},
			want: "struct __xar_t",
		},
		{
			name: "Test struct 2",
			args: args{
				encType: "{?=\"val\"[8I]}",
			},
			want: "struct { unsigned int val[8]; }",
		},
		{
			name: "Test struct 3",
			args: args{
				encType: "^{?}",
			},
			want: "void * /* struct */",
		},
		{
			name: "Test struct 4",
			args: args{
				encType: "{__CFRuntimeBase=QAQ}",
			},
			want: "struct __CFRuntimeBase { unsigned long long x0; _Atomic unsigned long long x1; }",
		},
		{
			name: "Test struct 4",
			args: args{
				encType: "{__cfobservers_t=\"slot\"@\"next\"^{__cfobservers_t}}",
			},
			want: "struct __cfobservers_t { id slot; struct __cfobservers_t *next; }",
		},
		{
			name: "Test struct 5",
			args: args{
				encType: "{_UISmallVector<unsigned short, 16UL>=\"_vector\"\"_size\"Q}",
			},
			want: "struct _UISmallVector<unsigned short, 16UL> { id _vector; unsigned long long _size; }",
		},
		{
			name: "Test union 0",
			args: args{
				encType: "(?=i)",
			},
			want: "union { int x0; }",
		},
		{
			name: "Test union 1",
			args: args{
				encType: "(?=\"fat\"^S\"thin\"*)",
			},
			want: "union { unsigned short *fat; char *thin; }",
		},
		{
			name: "Test union 2",
			args: args{
				encType: "^(?)",
			},
			want: "void * /* union */",
		},
		{
			name: "Test union 3",
			args: args{
				encType: "(?=\"xpc\"@\"NSObject<OS_xpc_object>\"\"remote\"@\"OS_xpc_remote_connection\")",
			},
			want: "union { NSObject<OS_xpc_object> *xpc; OS_xpc_remote_connection *remote; }",
		},
		{
			name: "Test block",
			args: args{
				encType: "@?",
			},
			want: "id /* block */",
		},
		{
			name: "Test vector 0",
			args: args{
				encType: "![16,8i]",
			},
			want: "int x __attribute__((aligned(8), vector_size(16)))",
		},
		{
			name: "Test vector 1",
			args: args{
				encType: "^![16,8c]",
			},
			want: "signed char *x __attribute__((aligned(8), vector_size(16)))",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeType(tt.args.encType); got != tt.want {
				t.Errorf("decodeType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCutType_Truncated verifies CutType does not panic on malformed or
// truncated type encodings (e.g. garbage read from a method's typesOffset).
// Previously these inputs caused "index out of range" panics.
func TestCutType_Truncated(t *testing.T) {
	cases := []string{
		"",            // empty
		"!",           // vector marker only
		"!,",          // vector, no dimensions/subtype
		"![16,8",      // vector, unterminated
		"[",           // array marker only
		"[12",         // array, digits but no subtype/close
		"[12^v",       // array, unterminated
		"@\"",         // object class name, no closing quote
		"@\"NSString", // object class name, unterminated
		"{",           // struct marker only
		"{Foo=",       // struct, unterminated
		"(",           // union marker only
		"<",           // block prototype marker only
		"b",           // bitfield marker only
		"^",           // pointer marker only
		// Prefix specifier(s) followed by an unterminated aggregate at the end
		// of the string: the prefix advances the cursor so the aggregate's close
		// delimiter is missing AND the computed slice end runs one past the
		// buffer. These cases panicked until every bracket case was clamped.
		"^{",   // pointer + unterminated struct
		"r(",   // const + unterminated union
		"n<",   // in + unterminated block prototype
		"^^(",  // pointer + pointer + unterminated union
		"NO<",  // inout + bycopy + unterminated block prototype
		"r[",   // const + unterminated array
		"^!",   // pointer + unterminated vector
		"A@\"", // _Atomic + unterminated class name
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			// Must not panic; just exercise the parser.
			head, rest, ok := CutType(in)
			_ = head
			_ = rest
			_ = ok
		})
	}
}

// TestArgumentTypeIndexing locks in the index contract that callers rely on:
// ArgumentType indexes the full method type encoding, so index 0 is the return
// type, 1 is self, 2 is _cmd/SEL, and the real arguments run from index 3
// through NumberOfArguments() inclusive (one past that is out of range).
func TestArgumentTypeIndexing(t *testing.T) {
	// void method with two object arguments.
	m := &Method{Types: "v32@0:8@16@24"}
	if got := m.NumberOfArguments(); got != 4 {
		t.Fatalf("NumberOfArguments() = %d, want 4", got)
	}
	want := map[int]string{0: "void", 1: "id", 2: "SEL", 3: "id", 4: "id"}
	for idx, exp := range want {
		if got := m.ArgumentType(idx); got != exp {
			t.Errorf("ArgumentType(%d) = %q, want %q", idx, got, exp)
		}
	}
	// The last real argument (index == NumberOfArguments()) must be reachable;
	// regression guard for the off-by-one that dropped it.
	if got := m.ArgumentType(m.NumberOfArguments()); got != "id" {
		t.Errorf("ArgumentType(NumberOfArguments()) = %q, want %q", got, "id")
	}
	// Out-of-range indices return the sentinel rather than panicking.
	if got := m.ArgumentType(5); got != "<error>" {
		t.Errorf("ArgumentType(5) = %q, want %q", got, "<error>")
	}
	if got := m.ArgumentType(-1); got != "<error>" {
		t.Errorf("ArgumentType(-1) = %q, want %q", got, "<error>")
	}
}

// TestArgumentTypeMalformedNoPanic verifies the parser-disagreement boundary:
// for "v16@0:8^^" getNumberOfArguments counts the trailing "^^" as an argument
// (NumberOfArguments()==3) but the argument decoder drops that dangling prefix
// (getArguments yields only 3 entries: return type, self, _cmd). Indexing
// ArgumentType at NumberOfArguments() therefore lands one past the decoded args
// and must return the "<error>" sentinel instead of panicking — the boundary
// fillImportsForMethod stops at.
func TestArgumentTypeMalformedNoPanic(t *testing.T) {
	m := &Method{Types: "v16@0:8^^"} // trailing pointer-prefix with no pointee
	n := m.NumberOfArguments()
	if got := m.ArgumentType(n); got != "<error>" {
		t.Errorf("ArgumentType(%d) = %q, want %q", n, got, "<error>")
	}
}
