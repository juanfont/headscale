package types

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestNewSSHCheckAuthRequestBinding verifies that an SSH-check [AuthRequest]
// captures the (src, dst) node pair at construction time and rejects
// callers that try to read [AuthRequest.RegistrationData] from it.
func TestNewSSHCheckAuthRequestBinding(t *testing.T) {
	const src, dst NodeID = 7, 11

	req := NewSSHCheckAuthRequest(src, dst)

	require.True(t, req.IsSSHCheck(), "SSH-check request must report IsSSHCheck=true")
	require.False(t, req.IsRegistration(), "SSH-check request must not report IsRegistration")

	binding := req.SSHCheckBinding()
	assert.Equal(t, src, binding.SrcNodeID, "SrcNodeID must match")
	assert.Equal(t, dst, binding.DstNodeID, "DstNodeID must match")

	assert.Panics(t, func() {
		_ = req.RegistrationData()
	}, "RegistrationData() must panic on an SSH-check AuthRequest")
}

// TestNewRegisterAuthRequestPayload verifies that a registration
// [AuthRequest] carries the supplied [RegistrationData] and rejects callers
// that try to read SSH-check binding from it.
func TestNewRegisterAuthRequestPayload(t *testing.T) {
	data := &RegistrationData{Hostname: "node-a"}

	req := NewRegisterAuthRequest(data)

	require.True(t, req.IsRegistration(), "registration request must report IsRegistration=true")
	require.False(t, req.IsSSHCheck(), "registration request must not report IsSSHCheck")
	assert.Same(t, data, req.RegistrationData(), "RegistrationData() must return the supplied pointer")

	assert.Panics(t, func() {
		_ = req.SSHCheckBinding()
	}, "SSHCheckBinding() must panic on a registration AuthRequest")
}

func TestAuthRequestPrepareForCacheOwnsRegistration(t *testing.T) {
	expiry := time.Date(2027, time.January, 2, 3, 4, 5, 6, time.UTC)
	data := &RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		DiscoKey:   key.NewDisco().Public(),
		Hostname:   "router-a",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:     "router-a",
			IPNVersion:   "1.104.0",
			OS:           "linux",
			OSVersion:    "6.18.0",
			Distro:       "nixos",
			Container:    "false",
			Userspace:    "true",
			RequestTags:  []string{"tag:router", "tag:production"},
			RoutableIPs:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8::/64")},
			WoLMACs:      []string{"00:11:22:33:44:55"},
			Services:     []tailcfg.Service{{Proto: tailcfg.TCP, Port: 22, Description: "ssh"}},
			SSH_HostKeys: []string{"ssh-ed25519 initial-host-key"},
			NetInfo: &tailcfg.NetInfo{
				WorkingUDP:    "true",
				WorkingIPv6:   "false",
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.01, "2-v6": 0.02},
			},
			Location: &tailcfg.Location{Country: "Norway", City: "Tromsø", Latitude: 69.65, Longitude: 18.96},
			TPM:      &tailcfg.TPMInfo{Manufacturer: "MSFT", Model: 1},
		},
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641"), netip.MustParseAddrPort("[2001:db8::1]:41641")},
		Expiry:    &expiry,
	}
	want := *data
	want.Hostinfo = data.Hostinfo.Clone()
	want.Endpoints = append([]netip.AddrPort(nil), data.Endpoints...)
	wantExpiry := expiry
	want.Expiry = &wantExpiry

	req := NewRegisterAuthRequest(data)
	require.NoError(t, req.PrepareForCache())
	assert.True(t, req.IsRegistration())
	assert.False(t, req.IsSSHCheck())
	assert.Nil(t, req.regData, "prepared requests must release the decoded payload")
	assert.Equal(t, &want, req.RegistrationData())

	data.Hostname = "changed"
	data.Hostinfo.RequestTags[0] = "tag:changed"
	data.Hostinfo.RoutableIPs[0] = netip.MustParsePrefix("192.0.2.0/24")
	data.Hostinfo.Services[0].Description = "changed"
	data.Hostinfo.NetInfo.DERPLatency["1-v4"] = 1
	data.Hostinfo.Location.City = "changed"
	data.Hostinfo.TPM.Manufacturer = "changed"
	data.Endpoints[0] = netip.MustParseAddrPort("192.0.2.2:1")
	*data.Expiry = time.Time{}

	assert.Equal(t, &want, req.RegistrationData(), "the producer must not retain ownership of cached data")

	got := req.RegistrationData()
	got.Hostname = "changed by consumer"
	got.Hostinfo.RequestTags[0] = "tag:consumer"
	got.Hostinfo.Services[0].Description = "changed by consumer"
	got.Hostinfo.NetInfo.DERPLatency["1-v4"] = 2
	got.Endpoints[0] = netip.MustParseAddrPort("192.0.2.3:1")
	*got.Expiry = time.Time{}

	require.NoError(t, req.PrepareForCache())
	assert.Equal(t, &want, req.RegistrationData(), "access and repeated preparation must leave cached data unchanged")
}

func TestAuthRequestPrepareForCachePayloadLimit(t *testing.T) {
	const limit = MaxRegistrationPayloadBytes

	for _, test := range []struct {
		name string
		size int
	}{
		{name: "below limit", size: limit - 1},
		{name: "exact limit", size: limit},
		{name: "over limit", size: limit + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := &RegistrationData{Hostinfo: &tailcfg.Hostinfo{OS: "linux"}}
			base, err := json.Marshal(data)
			require.NoError(t, err)

			data.Hostinfo.OS = strings.Repeat("a", test.size-len(base)+len(data.Hostinfo.OS))
			encoded, err := json.Marshal(data)
			require.NoError(t, err)
			require.Len(t, encoded, test.size)

			req := NewRegisterAuthRequest(data)

			err = req.PrepareForCache()
			if test.size > limit {
				require.ErrorIs(t, err, ErrRegistrationPayloadTooLarge, "oversize payloads must be rejected instead of truncated")
				assert.Empty(t, req.regDataJSON)
				assert.Same(t, data, req.RegistrationData(), "failed preparation must leave the original data intact")

				return
			}

			require.NoError(t, err)
			assert.Nil(t, req.regData)
			assert.Len(t, req.regDataJSON, test.size)
			assert.Equal(t, data, req.RegistrationData())
		})
	}
}

func TestAuthRequestPrepareForCacheRouteAndServiceMetadata(t *testing.T) {
	data := &RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "regional-router",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    "regional-router",
			OS:          "linux",
			OSVersion:   "6.18.0",
			IPNVersion:  "1.104.0",
			RequestTags: []string{"tag:router", "tag:production"},
		},
	}
	for i := range 128 {
		data.Hostinfo.RoutableIPs = append(data.Hostinfo.RoutableIPs,
			netip.MustParsePrefix(fmt.Sprintf("10.42.%d.0/24", i)),
			netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/64", i)))
	}

	for port := uint16(8000); port < 8064; port++ {
		data.Hostinfo.Services = append(data.Hostinfo.Services, tailcfg.Service{
			Proto:       tailcfg.TCP,
			Port:        port,
			Description: fmt.Sprintf("regional-service-%d", port),
		})
	}

	req := NewRegisterAuthRequest(data)
	require.NoError(t, req.PrepareForCache())
	assert.Nil(t, req.regData)
	assert.LessOrEqual(t, len(req.regDataJSON), MaxRegistrationPayloadBytes)
	assert.Equal(t, data, req.RegistrationData())
}

func TestAuthRequestPrepareForCacheInvalidPayload(t *testing.T) {
	invalidExpiry := time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		data *RegistrationData
	}{
		{name: "invalid expiry", data: &RegistrationData{Expiry: &invalidExpiry}},
		{name: "invalid latency", data: &RegistrationData{Hostinfo: &tailcfg.Hostinfo{
			NetInfo: &tailcfg.NetInfo{DERPLatency: map[string]float64{"1-v4": math.NaN()}},
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := NewRegisterAuthRequest(test.data)
			require.Error(t, req.PrepareForCache())
			assert.Empty(t, req.regDataJSON)
			assert.Same(t, test.data, req.RegistrationData())
		})
	}
}

func TestAuthRequestPrepareForCacheNilValues(t *testing.T) {
	for _, data := range []*RegistrationData{
		{},
		{Hostinfo: &tailcfg.Hostinfo{}},
		{Hostinfo: &tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{}}},
		{Expiry: &time.Time{}},
		{Endpoints: []netip.AddrPort{}},
	} {
		req := NewRegisterAuthRequest(data)
		require.NoError(t, req.PrepareForCache())
		assert.True(t, req.IsRegistration())
		assert.Equal(t, data, req.RegistrationData())
	}

	for _, req := range []*AuthRequest{NewAuthRequest(), NewRegisterAuthRequest(nil), NewSSHCheckAuthRequest(7, 11)} {
		require.NoError(t, req.PrepareForCache())
		require.NoError(t, req.PrepareForCache())
		assert.False(t, req.IsRegistration())
		assert.Panics(t, func() { _ = req.RegistrationData() })

		if req.IsSSHCheck() {
			assert.Equal(t, &SSHCheckBinding{SrcNodeID: 7, DstNodeID: 11}, req.SSHCheckBinding())
		}
	}
}

// TestNewAuthRequestEmptyPayload verifies that a payload-less
// [AuthRequest] reports both Is* helpers as false and panics on either
// payload accessor.
func TestNewAuthRequestEmptyPayload(t *testing.T) {
	req := NewAuthRequest()

	assert.False(t, req.IsRegistration())
	assert.False(t, req.IsSSHCheck())

	assert.Panics(t, func() { _ = req.RegistrationData() })
	assert.Panics(t, func() { _ = req.SSHCheckBinding() })
}

// TestPendingRegistrationConfirmation verifies that the OIDC callback
// can stash a pending confirmation onto an [AuthRequest] and that the
// /register/confirm POST handler can read it back unchanged.
func TestPendingRegistrationConfirmation(t *testing.T) {
	req := NewRegisterAuthRequest(&RegistrationData{Hostname: "phish-test"})

	require.Nil(t, req.PendingConfirmation(),
		"new AuthRequest must have no pending confirmation")

	pending := &PendingRegistrationConfirmation{
		UserID: 42,
		CSRF:   "csrf-marker",
	}
	req.SetPendingConfirmation(pending)

	got := req.PendingConfirmation()
	require.NotNil(t, got, "PendingConfirmation must return the stored value")
	assert.Equal(t, uint(42), got.UserID)
	assert.Equal(t, "csrf-marker", got.CSRF)
}

func TestDefaultBatcherWorkersFor(t *testing.T) {
	tests := []struct {
		cpuCount int
		expected int
	}{
		{1, 1},   // (1*3)/4 = 0, should be minimum 1
		{2, 1},   // (2*3)/4 = 1
		{4, 3},   // (4*3)/4 = 3
		{8, 6},   // (8*3)/4 = 6
		{12, 9},  // (12*3)/4 = 9
		{16, 12}, // (16*3)/4 = 12
		{20, 15}, // (20*3)/4 = 15
		{24, 18}, // (24*3)/4 = 18
	}

	for _, test := range tests {
		result := DefaultBatcherWorkersFor(test.cpuCount)
		if result != test.expected {
			t.Errorf("DefaultBatcherWorkersFor(%d) = %d, expected %d", test.cpuCount, result, test.expected)
		}
	}
}

func TestDefaultBatcherWorkers(t *testing.T) {
	// Just verify it returns a valid value (>= 1)
	result := DefaultBatcherWorkers()
	if result < 1 {
		t.Errorf("DefaultBatcherWorkers() = %d, expected value >= 1", result)
	}
}
