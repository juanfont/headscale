// Code generated manually to provide types for PendingRegistrations RPC until buf generate is run.
// This file defines protobuf-compatible Go structs without full reflection metadata.
// It is sufficient for compiling server code that references these types.

package v1

import (
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// PendingRegistration is a lightweight representation of a pending registration.
type PendingRegistration struct {
	Id         string                  `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Hostname   string                  `protobuf:"bytes,2,opt,name=hostname,proto3" json:"hostname,omitempty"`
	MachineKey string                  `protobuf:"bytes,3,opt,name=machine_key,json=machineKey,proto3" json:"machine_key,omitempty"`
	NodeKey    string                  `protobuf:"bytes,4,opt,name=node_key,json=nodeKey,proto3" json:"node_key,omitempty"`
	Expiry     *timestamppb.Timestamp  `protobuf:"bytes,5,opt,name=expiry,proto3" json:"expiry,omitempty"`
}

// ListPendingRegistrationsRequest is the empty request message.
type ListPendingRegistrationsRequest struct{}

// ListPendingRegistrationsResponse contains the current pending registrations.
type ListPendingRegistrationsResponse struct {
	Registrations []*PendingRegistration `protobuf:"bytes,1,rep,name=registrations,proto3" json:"registrations,omitempty"`
}
