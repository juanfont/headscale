package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

var (
	ErrWireGuardConnectionNotFound      = errors.New("wireguard connection not found")
	ErrWireGuardConnectionAlreadyExists = errors.New("wireguard connection already exists")
)

// CreateWireGuardConnection creates a new connection between a node and a WireGuard-only peer.
// The connection includes per-node masquerade addresses for bidirectional routing.
func (hsdb *HSDatabase) CreateWireGuardConnection(conn *types.WireGuardConnection) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return CreateWireGuardConnection(tx, conn)
	})
}

func CreateWireGuardConnection(tx *gorm.DB, conn *types.WireGuardConnection) error {
	if err := conn.Validate(); err != nil {
		return fmt.Errorf("validating connection: %w", err)
	}

	// Check if connection already exists
	var existing types.WireGuardConnection
	err := tx.Where("node_id = ? AND wg_peer_id = ?", conn.NodeID, conn.WGPeerID).
		First(&existing).Error
	if err == nil {
		return ErrWireGuardConnectionAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("checking for existing connection: %w", err)
	}

	conn.CreatedAt = time.Now().UTC()

	if err := tx.Create(conn).Error; err != nil {
		return fmt.Errorf("creating wireguard connection: %w", err)
	}

	return nil
}

// DeleteWireGuardConnection removes a connection between a node and a WireGuard-only peer.
func (hsdb *HSDatabase) DeleteWireGuardConnection(nodeID, wgPeerID types.NodeID) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteWireGuardConnection(tx, nodeID, wgPeerID)
	})
}

func DeleteWireGuardConnection(tx *gorm.DB, nodeID, wgPeerID types.NodeID) error {
	result := tx.Where("node_id = ? AND wg_peer_id = ?", nodeID, wgPeerID).
		Delete(&types.WireGuardConnection{})

	if result.Error != nil {
		return fmt.Errorf("deleting wireguard connection: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrWireGuardConnectionNotFound
	}

	return nil
}

// ListAllWireGuardConnections returns all connections in the database.
// This is used for initial NodeStore loading and should not be called in hot paths.
func (hsdb *HSDatabase) ListAllWireGuardConnections() (types.WireGuardConnections, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.WireGuardConnections, error) {
		return ListAllWireGuardConnections(rx)
	})
}

func ListAllWireGuardConnections(tx *gorm.DB) (types.WireGuardConnections, error) {
	var connections types.WireGuardConnections

	if err := tx.Find(&connections).Error; err != nil {
		return nil, fmt.Errorf("listing all wireguard connections: %w", err)
	}

	return connections, nil
}
