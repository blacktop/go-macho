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
			name: "Test array",
			args: args{
				encType: "[2]",
			},
			want: "void * x[2]",
		},
		{
			name: "Test bitfield",
			args: args{
				encType: "b13",
			},
			want: "int x : 13",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeType(tt.args.encType); got != tt.want {
				t.Errorf("decodeType() = %v, want %v", got, tt.want)
			}
		})
	}
}
