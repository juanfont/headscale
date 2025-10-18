package db

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

var (
	ErrWireGuardOnlyPeerNotFound      = errors.New("wireguard-only peer not found")
	ErrWireGuardOnlyPeerAlreadyExists = errors.New("wireguard-only peer with this name already exists")
	ErrWireGuardOnlyPeerInvalidMasqAddr = errors.New("at least one masquerade address (IPv4 or IPv6) must be specified")
)

// CreateWireGuardOnlyPeer creates a new WireGuard-only peer in the database.
// NOTE: The peer's IPv4 and IPv6 addresses must already be allocated before calling this function.
// Use State.CreateWireGuardOnlyPeer instead for the full creation flow including IP allocation.
//
// IMPORTANT: WireGuard-only peers BYPASS ACL POLICIES. They are explicitly
// configured by administrators and access control is managed solely through
// the KnownNodeIDs field.
func (hsdb *HSDatabase) CreateWireGuardOnlyPeer(peer *types.WireGuardOnlyPeer) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return CreateWireGuardOnlyPeer(tx, peer)
	})
}

func CreateWireGuardOnlyPeer(tx *gorm.DB, peer *types.WireGuardOnlyPeer) error {
	if err := peer.Validate(); err != nil {
		return fmt.Errorf("validating wireguard-only peer: %w", err)
	}

	if peer.IPv4 == nil && peer.IPv6 == nil {
		return fmt.Errorf("peer must have at least one IP address allocated")
	}

	var existing types.WireGuardOnlyPeer
	err := tx.Where("name = ?", peer.Name).First(&existing).Error
	if err == nil {
		return ErrWireGuardOnlyPeerAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("checking for existing peer: %w", err)
	}

	if err := tx.Create(peer).Error; err != nil {
		return fmt.Errorf("creating wireguard-only peer: %w", err)
	}

	return nil
}

func (hsdb *HSDatabase) GetWireGuardOnlyPeerByID(id uint64) (*types.WireGuardOnlyPeer, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.WireGuardOnlyPeer, error) {
		return GetWireGuardOnlyPeerByID(rx, id)
	})
}

func GetWireGuardOnlyPeerByID(tx *gorm.DB, id uint64) (*types.WireGuardOnlyPeer, error) {
	var peer types.WireGuardOnlyPeer
	if err := tx.Preload("User").Where("id = ?", id).First(&peer).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrWireGuardOnlyPeerNotFound
		}
		return nil, fmt.Errorf("getting wireguard-only peer: %w", err)
	}

	return &peer, nil
}

func (hsdb *HSDatabase) GetWireGuardOnlyPeerByName(name string) (*types.WireGuardOnlyPeer, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.WireGuardOnlyPeer, error) {
		return GetWireGuardOnlyPeerByName(rx, name)
	})
}

func GetWireGuardOnlyPeerByName(tx *gorm.DB, name string) (*types.WireGuardOnlyPeer, error) {
	var peer types.WireGuardOnlyPeer
	if err := tx.Preload("User").Where("name = ?", name).First(&peer).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrWireGuardOnlyPeerNotFound
		}
		return nil, fmt.Errorf("getting wireguard-only peer: %w", err)
	}

	return &peer, nil
}

func (hsdb *HSDatabase) ListWireGuardOnlyPeers(userID *uint) (types.WireGuardOnlyPeers, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.WireGuardOnlyPeers, error) {
		return ListWireGuardOnlyPeers(rx, userID)
	})
}

func ListWireGuardOnlyPeers(tx *gorm.DB, userID *uint) (types.WireGuardOnlyPeers, error) {
	var peers types.WireGuardOnlyPeers

	query := tx.Preload("User")
	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	}

	if err := query.Find(&peers).Error; err != nil {
		return nil, fmt.Errorf("listing wireguard-only peers: %w", err)
	}

	return peers, nil
}

// ListWireGuardOnlyPeersForNode returns all WireGuard-only peers that a given
// node should be able to see. A node can see a WG-only peer if the node's ID
// is in the peer's KnownNodeIDs list.
func (hsdb *HSDatabase) ListWireGuardOnlyPeersForNode(nodeID types.NodeID) (types.WireGuardOnlyPeers, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.WireGuardOnlyPeers, error) {
		return ListWireGuardOnlyPeersForNode(rx, nodeID)
	})
}

func ListWireGuardOnlyPeersForNode(tx *gorm.DB, nodeID types.NodeID) (types.WireGuardOnlyPeers, error) {
	var allPeers types.WireGuardOnlyPeers
	if err := tx.Preload("User").Find(&allPeers).Error; err != nil {
		return nil, fmt.Errorf("listing all wireguard-only peers: %w", err)
	}

	var visiblePeers types.WireGuardOnlyPeers
	for _, peer := range allPeers {
		for _, knownID := range peer.KnownNodeIDs {
			if types.NodeID(knownID) == nodeID {
				visiblePeers = append(visiblePeers, peer)
				break
			}
		}
	}

	return visiblePeers, nil
}

// UpdateWireGuardOnlyPeer updates an existing WireGuard-only peer.
// Note: This is not exposed via CLI in the initial implementation, but is
// provided for future use.
func (hsdb *HSDatabase) UpdateWireGuardOnlyPeer(peer *types.WireGuardOnlyPeer) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return UpdateWireGuardOnlyPeer(tx, peer)
	})
}

func UpdateWireGuardOnlyPeer(tx *gorm.DB, peer *types.WireGuardOnlyPeer) error {
	if err := peer.Validate(); err != nil {
		return fmt.Errorf("validating wireguard-only peer: %w", err)
	}

	if err := tx.Save(peer).Error; err != nil {
		return fmt.Errorf("updating wireguard-only peer: %w", err)
	}

	return nil
}

func (hsdb *HSDatabase) DeleteWireGuardOnlyPeer(id uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteWireGuardOnlyPeer(tx, id)
	})
}

func DeleteWireGuardOnlyPeer(tx *gorm.DB, id uint64) error {
	result := tx.Where("id = ?", id).Delete(&types.WireGuardOnlyPeer{})
	if result.Error != nil {
		return fmt.Errorf("deleting wireguard-only peer: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrWireGuardOnlyPeerNotFound
	}

	return nil
}
