package cli

import "testing"

func TestClientBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{
			name:    "bare host defaults to https",
			address: "headscale.example.com:50443",
			want:    "https://headscale.example.com:50443",
		},
		{
			name:    "explicit https scheme is kept",
			address: "https://headscale.example.com",
			want:    "https://headscale.example.com",
		},
		{
			name:    "explicit http scheme is kept",
			address: "http://localhost:8080",
			want:    "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientBaseURL(tt.address); got != tt.want {
				t.Errorf("clientBaseURL(%q) = %q, want %q", tt.address, got, tt.want)
			}
		})
	}
}
