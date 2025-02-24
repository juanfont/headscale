package tsic

import "testing"

func TestParseLoginURL(t *testing.T) {
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
			gotURL, err := parseLoginURL(tt.output)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("parseLoginURL() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("parseLoginURL() error = %v, wantErr %v", err, tt.wantErr)
				}
				if gotURL.String() != tt.wantURL {
					t.Errorf("parseLoginURL() = %v, want %v", gotURL, tt.wantURL)
				}
			}
		})
	}
}
