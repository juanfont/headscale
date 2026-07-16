package dns

import "testing"

func TestRelativeRecordName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fqdn    string
		zone    string
		want    string
		wantErr bool
	}{
		{
			name: "acme challenge under zone",
			fqdn: "_acme-challenge.node1.mesh.neogcs.com",
			zone: "mesh.neogcs.com",
			want: "_acme-challenge.node1",
		},
		{
			name: "trailing dots",
			fqdn: "_acme-challenge.node1.mesh.neogcs.com.",
			zone: "mesh.neogcs.com.",
			want: "_acme-challenge.node1",
		},
		{
			name:    "outside zone",
			fqdn:    "_acme-challenge.node1.other.com",
			zone:    "mesh.neogcs.com",
			wantErr: true,
		},
		{
			name: "apex",
			fqdn: "mesh.neogcs.com",
			zone: "mesh.neogcs.com",
			want: "@",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := RelativeRecordName(tt.fqdn, tt.zone)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
