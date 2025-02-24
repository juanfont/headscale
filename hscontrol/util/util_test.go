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

func TestParseLoginURLFromCLILogin(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantURL string
		wantErr string
	}{
		{
			name: "valid https URL",
			output: `
To authenticate, visit:

        https://headscale.example.com/register/3oYCOZYA2zZmGB4PQ7aHBaMi

Success.`,
			wantURL: "https://headscale.example.com/register/3oYCOZYA2zZmGB4PQ7aHBaMi",
			wantErr: "",
		},
		{
			name: "valid http URL",
			output: `
To authenticate, visit:

        http://headscale.example.com/register/3oYCOZYA2zZmGB4PQ7aHBaMi

Success.`,
			wantURL: "http://headscale.example.com/register/3oYCOZYA2zZmGB4PQ7aHBaMi",
			wantErr: "",
		},
		{
			name: "no URL",
			output: `
To authenticate, visit:

Success.`,
			wantURL: "",
			wantErr: "no URL found",
		},
		{
			name: "multiple URLs",
			output: `
To authenticate, visit:

        https://headscale.example.com/register/3oYCOZYA2zZmGB4PQ7aHBaMi

To authenticate, visit:

        http://headscale.example.com/register/dv1l2k5FackOYl-7-V3mSd_E

Success.`,
			wantURL: "",
			wantErr: "multiple URLs found: https://headscale.example.com/register/3oYCOZYA2zZmGB4PQ7aHBaMi and http://headscale.example.com/register/dv1l2k5FackOYl-7-V3mSd_E",
		},
		{
			name: "invalid URL",
			output: `
To authenticate, visit:

        invalid-url

Success.`,
			wantURL: "",
			wantErr: "no URL found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, err := ParseLoginURLFromCLILogin(tt.output)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("ParseLoginURLFromCLILogin() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("ParseLoginURLFromCLILogin() error = %v, wantErr %v", err, tt.wantErr)
				}
				if gotURL.String() != tt.wantURL {
					t.Errorf("ParseLoginURLFromCLILogin() = %v, want %v", gotURL, tt.wantURL)
				}
			}
		})
	}
}
