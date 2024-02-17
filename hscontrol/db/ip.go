package db

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"gorm.io/gorm"
)

// IPAllocator is a singleton responsible for allocating
// IP addresses for nodes and making sure the same
// address is not handed out twice. There can only be one
// and it needs to be created before any other database
// writes occur.
type IPAllocator struct {
	mu sync.Mutex

	prefix4 netip.Prefix
	prefix6 netip.Prefix

	// Previous IPs handed out
	prev4 netip.Addr
	prev6 netip.Addr

	// Set of all IPs handed out.
	// This might not be in sync with the database,
	// but it is more conservative. If saves to the
	// database fails, the IP will be allocated here
	// until the next restart of Headscale.
	usedIPs netipx.IPSetBuilder
}

// NewIPAllocator returns a new IPAllocator singleton which
// can be used to hand out unique IP addresses within the
// provided IPv4 and IPv6 prefix. It needs to be created
// when headscale starts and needs to finish its read
// transaction before any writes to the database occur.
func NewIPAllocator(db *HSDatabase, prefix4, prefix6 netip.Prefix) (*IPAllocator, error) {
	var addressesSlices []string

	if db != nil {
		db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ip_addresses", &addressesSlices).Error
		})
	}

	var ips netipx.IPSetBuilder

	// Add network and broadcast addrs to used pool so they
	// are not handed out to nodes.
	network4, broadcast4 := util.GetIPPrefixEndpoints(prefix4)
	network6, broadcast6 := util.GetIPPrefixEndpoints(prefix6)
	ips.Add(network4)
	ips.Add(broadcast4)
	ips.Add(network6)
	ips.Add(broadcast6)

	// Fetch all the IP Addresses currently handed out from the Database
	// and add them to the used IP set.
	for _, slice := range addressesSlices {
		var machineAddresses types.NodeAddresses
		err := machineAddresses.Scan(slice)
		if err != nil {
			return nil, fmt.Errorf(
				"parsing IPs from database %v: %w", machineAddresses,
				err,
			)
		}

		for _, ip := range machineAddresses {
			ips.Add(ip)
		}
	}

	// Build the initial IPSet to validate that we can use it.
	_, err := ips.IPSet()
	if err != nil {
		return nil, fmt.Errorf(
			"building initial IP Set: %w",
			err,
		)
	}

	return &IPAllocator{
		usedIPs: ips,

		prefix4: prefix4,
		prefix6: prefix6,

		// Use network as starting point, it will be used to call .Next()
		// TODO(kradalby): Could potentially take all the IPs loaded from
		// the database into account to start at a more "educated" location.
		prev4: network4,
		prev6: network6,
	}, nil
}

func (i *IPAllocator) Next() (types.NodeAddresses, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	v4, err := i.next(i.prev4, i.prefix4)
	if err != nil {
		return nil, fmt.Errorf("allocating IPv4 address: %w", err)
	}

	v6, err := i.next(i.prev6, i.prefix6)
	if err != nil {
		return nil, fmt.Errorf("allocating IPv6 address: %w", err)
	}

	return types.NodeAddresses{*v4, *v6}, nil
}

var ErrCouldNotAllocateIP = errors.New("failed to allocate IP")

func (i *IPAllocator) next(prev netip.Addr, prefix netip.Prefix) (*netip.Addr, error) {
	// Get the first IP in our prefix
	ip := prev.Next()

	// TODO(kradalby): maybe this can be done less often.
	set, err := i.usedIPs.IPSet()
	if err != nil {
		return nil, err
	}

	for {
		if !prefix.Contains(ip) {
			return nil, ErrCouldNotAllocateIP
		}

		// Check if the IP has already been allocated.
		if set.Contains(ip) {
			ip = ip.Next()

			continue
		}

		i.usedIPs.Add(ip)

		return &ip, nil
	}
}
