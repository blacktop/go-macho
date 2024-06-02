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
