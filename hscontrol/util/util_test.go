package util

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

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

func TestParseTraceroute(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Traceroute
		wantErr bool
	}{
		{
			name: "simple successful traceroute",
			input: `traceroute to 172.24.0.3 (172.24.0.3), 30 hops max, 46 byte packets
 1  ts-head-hk0urr.headscale.net (100.64.0.1)  1.135 ms  0.922 ms  0.619 ms
 2  172.24.0.3 (172.24.0.3)  0.593 ms  0.549 ms  0.522 ms`,
			want: Traceroute{
				Hostname: "172.24.0.3",
				IP:       netip.MustParseAddr("172.24.0.3"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "ts-head-hk0urr.headscale.net",
						IP:       netip.MustParseAddr("100.64.0.1"),
						Latencies: []time.Duration{
							1135 * time.Microsecond,
							922 * time.Microsecond,
							619 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "172.24.0.3",
						IP:       netip.MustParseAddr("172.24.0.3"),
						Latencies: []time.Duration{
							593 * time.Microsecond,
							549 * time.Microsecond,
							522 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "traceroute with timeouts",
			input: `traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  router.local (192.168.1.1)  1.234 ms  1.123 ms  1.121 ms
 2  * * *
 3  isp-gateway.net (10.0.0.1)  15.678 ms  14.789 ms  15.432 ms
 4  8.8.8.8 (8.8.8.8)  20.123 ms  19.876 ms  20.345 ms`,
			want: Traceroute{
				Hostname: "8.8.8.8",
				IP:       netip.MustParseAddr("8.8.8.8"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "router.local",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							1234 * time.Microsecond,
							1123 * time.Microsecond,
							1121 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "*",
					},
					{
						Hop:      3,
						Hostname: "isp-gateway.net",
						IP:       netip.MustParseAddr("10.0.0.1"),
						Latencies: []time.Duration{
							15678 * time.Microsecond,
							14789 * time.Microsecond,
							15432 * time.Microsecond,
						},
					},
					{
						Hop:      4,
						Hostname: "8.8.8.8",
						IP:       netip.MustParseAddr("8.8.8.8"),
						Latencies: []time.Duration{
							20123 * time.Microsecond,
							19876 * time.Microsecond,
							20345 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "unsuccessful traceroute",
			input: `traceroute to 10.0.0.99 (10.0.0.99), 5 hops max, 60 byte packets
 1  router.local (192.168.1.1)  1.234 ms  1.123 ms  1.121 ms
 2  * * *
 3  * * *
 4  * * *
 5  * * *`,
			want: Traceroute{
				Hostname: "10.0.0.99",
				IP:       netip.MustParseAddr("10.0.0.99"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "router.local",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							1234 * time.Microsecond,
							1123 * time.Microsecond,
							1121 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "*",
					},
					{
						Hop:      3,
						Hostname: "*",
					},
					{
						Hop:      4,
						Hostname: "*",
					},
					{
						Hop:      5,
						Hostname: "*",
					},
				},
				Success: false,
				Err:     errors.New("traceroute did not reach target"),
			},
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   "",
			want:    Traceroute{},
			wantErr: true,
		},
		{
			name:    "invalid header",
			input:   "not a valid traceroute output",
			want:    Traceroute{},
			wantErr: true,
		},
		{
			name: "windows tracert format",
			input: `Tracing route to google.com [8.8.8.8]
over a maximum of 30 hops:

  1    <1 ms    <1 ms    <1 ms  router.local [192.168.1.1]
  2     5 ms     4 ms     5 ms  10.0.0.1
  3     *        *        *     Request timed out.
  4    20 ms    19 ms    21 ms  8.8.8.8`,
			want: Traceroute{
				Hostname: "google.com",
				IP:       netip.MustParseAddr("8.8.8.8"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "router.local",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							1 * time.Millisecond,
							1 * time.Millisecond,
							1 * time.Millisecond,
						},
					},
					{
						Hop:      2,
						Hostname: "10.0.0.1",
						IP:       netip.MustParseAddr("10.0.0.1"),
						Latencies: []time.Duration{
							5 * time.Millisecond,
							4 * time.Millisecond,
							5 * time.Millisecond,
						},
					},
					{
						Hop:      3,
						Hostname: "*",
					},
					{
						Hop:      4,
						Hostname: "8.8.8.8",
						IP:       netip.MustParseAddr("8.8.8.8"),
						Latencies: []time.Duration{
							20 * time.Millisecond,
							19 * time.Millisecond,
							21 * time.Millisecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "mixed latency formats",
			input: `traceroute to 192.168.1.1 (192.168.1.1), 30 hops max, 60 byte packets
 1  gateway (192.168.1.1)  0.5 ms  *  0.4 ms`,
			want: Traceroute{
				Hostname: "192.168.1.1",
				IP:       netip.MustParseAddr("192.168.1.1"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "gateway",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							500 * time.Microsecond,
							400 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "only one latency value",
			input: `traceroute to 10.0.0.1 (10.0.0.1), 30 hops max, 60 byte packets
 1  10.0.0.1 (10.0.0.1)  1.5 ms`,
			want: Traceroute{
				Hostname: "10.0.0.1",
				IP:       netip.MustParseAddr("10.0.0.1"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "10.0.0.1",
						IP:       netip.MustParseAddr("10.0.0.1"),
						Latencies: []time.Duration{
							1500 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "backward compatibility - original format with 3 latencies",
			input: `traceroute to 172.24.0.3 (172.24.0.3), 30 hops max, 46 byte packets
 1  ts-head-hk0urr.headscale.net (100.64.0.1)  1.135 ms  0.922 ms  0.619 ms
 2  172.24.0.3 (172.24.0.3)  0.593 ms  0.549 ms  0.522 ms`,
			want: Traceroute{
				Hostname: "172.24.0.3",
				IP:       netip.MustParseAddr("172.24.0.3"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "ts-head-hk0urr.headscale.net",
						IP:       netip.MustParseAddr("100.64.0.1"),
						Latencies: []time.Duration{
							1135 * time.Microsecond,
							922 * time.Microsecond,
							619 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "172.24.0.3",
						IP:       netip.MustParseAddr("172.24.0.3"),
						Latencies: []time.Duration{
							593 * time.Microsecond,
							549 * time.Microsecond,
							522 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "two latencies only - common on packet loss",
			input: `traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  gateway (192.168.1.1)  1.2 ms  1.1 ms`,
			want: Traceroute{
				Hostname: "8.8.8.8",
				IP:       netip.MustParseAddr("8.8.8.8"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "gateway",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							1200 * time.Microsecond,
							1100 * time.Microsecond,
						},
					},
				},
				Success: false,
				Err:     errors.New("traceroute did not reach target"),
			},
			wantErr: false,
		},
		{
			name: "hostname without parentheses - some traceroute versions",
			input: `traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1  1.2 ms  1.1 ms  1.0 ms
 2  8.8.8.8  20.1 ms  19.9 ms  20.2 ms`,
			want: Traceroute{
				Hostname: "8.8.8.8",
				IP:       netip.MustParseAddr("8.8.8.8"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "192.168.1.1",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							1200 * time.Microsecond,
							1100 * time.Microsecond,
							1000 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "8.8.8.8",
						IP:       netip.MustParseAddr("8.8.8.8"),
						Latencies: []time.Duration{
							20100 * time.Microsecond,
							19900 * time.Microsecond,
							20200 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "ipv6 traceroute",
			input: `traceroute to 2001:4860:4860::8888 (2001:4860:4860::8888), 30 hops max, 80 byte packets
 1  2001:db8::1 (2001:db8::1)  1.123 ms  1.045 ms  0.987 ms
 2  2001:4860:4860::8888 (2001:4860:4860::8888)  15.234 ms  14.876 ms  15.123 ms`,
			want: Traceroute{
				Hostname: "2001:4860:4860::8888",
				IP:       netip.MustParseAddr("2001:4860:4860::8888"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "2001:db8::1",
						IP:       netip.MustParseAddr("2001:db8::1"),
						Latencies: []time.Duration{
							1123 * time.Microsecond,
							1045 * time.Microsecond,
							987 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "2001:4860:4860::8888",
						IP:       netip.MustParseAddr("2001:4860:4860::8888"),
						Latencies: []time.Duration{
							15234 * time.Microsecond,
							14876 * time.Microsecond,
							15123 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "macos traceroute with extra spacing",
			input: `traceroute to google.com (8.8.8.8), 64 hops max, 52 byte packets
 1  router.home (192.168.1.1)   2.345 ms   1.234 ms   1.567 ms
 2  * * *
 3  isp-gw.net (10.1.1.1)   15.234 ms   14.567 ms   15.890 ms
 4  google.com (8.8.8.8)   20.123 ms   19.456 ms   20.789 ms`,
			want: Traceroute{
				Hostname: "google.com",
				IP:       netip.MustParseAddr("8.8.8.8"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "router.home",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							2345 * time.Microsecond,
							1234 * time.Microsecond,
							1567 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "*",
					},
					{
						Hop:      3,
						Hostname: "isp-gw.net",
						IP:       netip.MustParseAddr("10.1.1.1"),
						Latencies: []time.Duration{
							15234 * time.Microsecond,
							14567 * time.Microsecond,
							15890 * time.Microsecond,
						},
					},
					{
						Hop:      4,
						Hostname: "google.com",
						IP:       netip.MustParseAddr("8.8.8.8"),
						Latencies: []time.Duration{
							20123 * time.Microsecond,
							19456 * time.Microsecond,
							20789 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "busybox traceroute minimal format",
			input: `traceroute to 10.0.0.1 (10.0.0.1), 30 hops max, 38 byte packets
 1  10.0.0.1 (10.0.0.1)  1.234 ms  1.123 ms  1.456 ms`,
			want: Traceroute{
				Hostname: "10.0.0.1",
				IP:       netip.MustParseAddr("10.0.0.1"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "10.0.0.1",
						IP:       netip.MustParseAddr("10.0.0.1"),
						Latencies: []time.Duration{
							1234 * time.Microsecond,
							1123 * time.Microsecond,
							1456 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "linux traceroute with dns failure fallback to IP",
			input: `traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.123 ms  1.098 ms
 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.432 ms  5.321 ms
 3  93.184.216.34 (93.184.216.34)  20.123 ms  19.876 ms  20.234 ms`,
			want: Traceroute{
				Hostname: "example.com",
				IP:       netip.MustParseAddr("93.184.216.34"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "192.168.1.1",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							1234 * time.Microsecond,
							1123 * time.Microsecond,
							1098 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "10.0.0.1",
						IP:       netip.MustParseAddr("10.0.0.1"),
						Latencies: []time.Duration{
							5678 * time.Microsecond,
							5432 * time.Microsecond,
							5321 * time.Microsecond,
						},
					},
					{
						Hop:      3,
						Hostname: "93.184.216.34",
						IP:       netip.MustParseAddr("93.184.216.34"),
						Latencies: []time.Duration{
							20123 * time.Microsecond,
							19876 * time.Microsecond,
							20234 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "alpine linux traceroute with ms variations",
			input: `traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 46 byte packets
 1  gateway (192.168.0.1)  0.456ms  0.389ms  0.412ms
 2  1.1.1.1 (1.1.1.1)  8.234ms  7.987ms  8.123ms`,
			want: Traceroute{
				Hostname: "1.1.1.1",
				IP:       netip.MustParseAddr("1.1.1.1"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "gateway",
						IP:       netip.MustParseAddr("192.168.0.1"),
						Latencies: []time.Duration{
							456 * time.Microsecond,
							389 * time.Microsecond,
							412 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "1.1.1.1",
						IP:       netip.MustParseAddr("1.1.1.1"),
						Latencies: []time.Duration{
							8234 * time.Microsecond,
							7987 * time.Microsecond,
							8123 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
		{
			name: "mixed asterisk and latency values",
			input: `traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  gateway (192.168.1.1)  *  1.234 ms  1.123 ms
 2  10.0.0.1 (10.0.0.1)  5.678 ms  *  5.432 ms
 3  8.8.8.8 (8.8.8.8)  20.123 ms  19.876 ms  *`,
			want: Traceroute{
				Hostname: "8.8.8.8",
				IP:       netip.MustParseAddr("8.8.8.8"),
				Route: []TraceroutePath{
					{
						Hop:      1,
						Hostname: "gateway",
						IP:       netip.MustParseAddr("192.168.1.1"),
						Latencies: []time.Duration{
							1234 * time.Microsecond,
							1123 * time.Microsecond,
						},
					},
					{
						Hop:      2,
						Hostname: "10.0.0.1",
						IP:       netip.MustParseAddr("10.0.0.1"),
						Latencies: []time.Duration{
							5678 * time.Microsecond,
							5432 * time.Microsecond,
						},
					},
					{
						Hop:      3,
						Hostname: "8.8.8.8",
						IP:       netip.MustParseAddr("8.8.8.8"),
						Latencies: []time.Duration{
							20123 * time.Microsecond,
							19876 * time.Microsecond,
						},
					},
				},
				Success: true,
				Err:     nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTraceroute(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTraceroute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Special handling for error field since it can't be directly compared with cmp.Diff
			gotErr := got.Err
			wantErr := tt.want.Err
			got.Err = nil
			tt.want.Err = nil

			if diff := cmp.Diff(tt.want, got, IPComparer); diff != "" {
				t.Errorf("ParseTraceroute() mismatch (-want +got):\n%s", diff)
			}

			// Now check error field separately
			if (gotErr == nil) != (wantErr == nil) {
				t.Errorf("Error field: got %v, want %v", gotErr, wantErr)
			} else if gotErr != nil && wantErr != nil && gotErr.Error() != wantErr.Error() {
				t.Errorf("Error message: got %q, want %q", gotErr.Error(), wantErr.Error())
			}
		})
	}
}
