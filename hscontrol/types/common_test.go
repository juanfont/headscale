package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSSHCheckAuthRequestBinding verifies that an SSH-check AuthRequest
// captures the (src, dst) node pair at construction time and rejects
// callers that try to read RegistrationData from it.
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
// AuthRequest carries the supplied RegistrationData and rejects callers
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

// TestNewAuthRequestEmptyPayload verifies that a payload-less
// AuthRequest reports both Is* helpers as false and panics on either
// payload accessor.
func TestNewAuthRequestEmptyPayload(t *testing.T) {
	req := NewAuthRequest()

	assert.False(t, req.IsRegistration())
	assert.False(t, req.IsSSHCheck())

	assert.Panics(t, func() { _ = req.RegistrationData() })
	assert.Panics(t, func() { _ = req.SSHCheckBinding() })
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
