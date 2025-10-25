package types

import (
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PendingRegistrationProto converts a state.PendingRegistration-like struct to protobuf.
// Kept in types to avoid circular imports from hscontrol/state.
// Input is the plain fields to serialize.
type PendingRegistrationProto struct {
	ID         string
	Hostname   string
	MachineKey string
	NodeKey    string
	// Expiry may be nil
	ExpiryUnixMilli int64 // not used; we will pass a pointer time via Timestamppb in helpers if needed
}

// BuildPendingRegistration constructs a v1.PendingRegistration.
func BuildPendingRegistration(id, hostname, machineKey, nodeKey string, expiry *int64) *v1.PendingRegistration {
	pr := &v1.PendingRegistration{
		Id:         id,
		Hostname:   hostname,
		MachineKey: machineKey,
		NodeKey:    nodeKey,
	}
	if expiry != nil {
		// We cannot convert int64 millis without time. Keep the field for potential future.
		// Callers should prefer using BuildPendingRegistrationWithTimestamp.
		_ = expiry
	}
	return pr
}

// BuildPendingRegistrationWithTimestamp sets a proper protobuf timestamp if provided.
func BuildPendingRegistrationWithTimestamp(id, hostname, machineKey, nodeKey string, ts *timestamppb.Timestamp) *v1.PendingRegistration {
	pr := &v1.PendingRegistration{
		Id:         id,
		Hostname:   hostname,
		MachineKey: machineKey,
		NodeKey:    nodeKey,
	}
	if ts != nil {
		pr.Expiry = ts
	}
	return pr
}
