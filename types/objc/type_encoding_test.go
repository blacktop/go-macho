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
				encType: "^{OutterStruct=(InnerUnion=q{InnerStruct=ii})b1b2b10b1q}",
			},
			want: "struct OutterStruct { union InnerUnion { long long x0; struct InnerStruct { int x0; int x1; } x1; } x0; unsigned int x1:1; unsigned int x2:2; unsigned int x3:10; unsigned int x4:1; long long x5; } *",
		},
		{
			name: "Test array",
			args: args{
				encType: "[2^v]",
			},
			want: "void * x[2]",
		},
		{
			name: "Test bitfield",
			args: args{
				encType: "b13",
			},
			want: "unsigned int x:13",
		},
		{
			name: "Test struct",
			args: args{
				encType: "{test=@*i}",
			},
			want: "struct test { id x0; char * x1; int x2; }",
		},
		{
			name: "Test union",
			args: args{
				encType: "(?=i)",
			},
			want: "union { int x0; }",
		},
		{
			name: "Test block",
			args: args{
				encType: "@?",
			},
			want: "id /* block */",
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
