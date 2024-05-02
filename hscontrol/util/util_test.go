package util

import "testing"

func TestTailscaleVersionNewerOrEqual(t *testing.T) {
	type args struct {
		minimum string
		toCheck string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "is-equal",
			args: args{
				minimum: "1.56",
				toCheck: "1.56",
			},
			want: true,
		},
		{
			name: "is-newer-head",
			args: args{
				minimum: "1.56",
				toCheck: "head",
			},
			want: true,
		},
		{
			name: "is-newer-unstable",
			args: args{
				minimum: "1.56",
				toCheck: "unstable",
			},
			want: true,
		},
		{
			name: "is-newer-patch",
			args: args{
				minimum: "1.56.1",
				toCheck: "1.56.1",
			},
			want: true,
		},
		{
			name: "is-older-patch-same-minor",
			args: args{
				minimum: "1.56.1",
				toCheck: "1.56.0",
			},
			want: false,
		},
		{
			name: "is-older-unstable",
			args: args{
				minimum: "1.56",
				toCheck: "1.55",
			},
			want: false,
		},
		{
			name: "is-older-one-stable",
			args: args{
				minimum: "1.56",
				toCheck: "1.54",
			},
			want: false,
		},
		{
			name: "is-older-five-stable",
			args: args{
				minimum: "1.56",
				toCheck: "1.46",
			},
			want: false,
		},
		{
			name: "is-older-patch",
			args: args{
				minimum: "1.56",
				toCheck: "1.48.1",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TailscaleVersionNewerOrEqual(tt.args.minimum, tt.args.toCheck); got != tt.want {
				t.Errorf("TailscaleVersionNewerThan() = %v, want %v", got, tt.want)
			}
		})
	}
}
