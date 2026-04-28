package db

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
)

var (
	errGeneratedIPBytesInvalid = errors.New("generated ip bytes are invalid ip")
	errGeneratedIPNotInPrefix  = errors.New("generated ip not in prefix")
	errIPAllocatorNil          = errors.New("ip allocator was nil")
)

// IPAllocator is a singleton responsible for allocating
// IP addresses for nodes and making sure the same
// address is not handed out twice. There can only be one
// and it needs to be created before any other database
// writes occur.
type IPAllocator struct {
	mu sync.Mutex

	prefix4 *netip.Prefix
	prefix6 *netip.Prefix

	// Previous IPs handed out
	prev4 netip.Addr
	prev6 netip.Addr

	// strategy used for handing out IP addresses.
	strategy types.IPAllocationStrategy

	// Set of all IPs handed out.
	// This might not be in sync with the database,
	// but it is more conservative. If saves to the
	// database fails, the IP will be allocated here
	// until the next restart of Headscale.
	usedIPs netipx.IPSetBuilder

	// nsPrefixes maps namespace name -> dedicated IPv4 prefix.
	// When set, nodes in that namespace are allocated from this prefix
	// instead of the global prefix4.
	nsPrefixes map[string]netip.Prefix

	// nsPrev tracks the previous IP handed out per namespace prefix.
	nsPrev map[string]netip.Addr

	// nsUsed tracks used IPs per namespace prefix (keyed by prefix string).
	nsUsed map[string]*netipx.IPSetBuilder
}

// NewIPAllocator returns a new IPAllocator singleton which
// can be used to hand out unique IP addresses within the
// provided IPv4 and IPv6 prefix. It needs to be created
// when headscale starts and needs to finish its read
// transaction before any writes to the database occur.
func NewIPAllocator(
	db *HSDatabase,
	prefix4, prefix6 *netip.Prefix,
	strategy types.IPAllocationStrategy,
	nsPrefixes map[string]netip.Prefix,
) (*IPAllocator, error) {
	ret := IPAllocator{
		prefix4:    prefix4,
		prefix6:    prefix6,
		strategy:   strategy,
		nsPrefixes: nsPrefixes,
		nsPrev:     make(map[string]netip.Addr),
		nsUsed:     make(map[string]*netipx.IPSetBuilder),
	}

	var (
		v4s []sql.NullString
		v6s []sql.NullString
	)

	if db != nil {
		err := db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ipv4", &v4s).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading IPv4 addresses from database: %w", err)
		}

		err = db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ipv6", &v6s).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading IPv6 addresses from database: %w", err)
		}
	}

	var ips netipx.IPSetBuilder

	// Add network and broadcast addrs to used pool so they
	// are not handed out to nodes.
	if prefix4 != nil {
		network4, broadcast4 := util.GetIPPrefixEndpoints(*prefix4)
		ips.Add(network4)
		ips.Add(broadcast4)

		// Use network as starting point, it will be used to call .Next()
		// TODO(kradalby): Could potentially take all the IPs loaded from
		// the database into account to start at a more "educated" location.
		ret.prev4 = network4
	}

	if prefix6 != nil {
		network6, broadcast6 := util.GetIPPrefixEndpoints(*prefix6)
		ips.Add(network6)
		ips.Add(broadcast6)

		ret.prev6 = network6
	}

	// Initialise per-namespace prefix pools: reserve network/broadcast addresses
	// and set the starting prev pointer for each namespace prefix.
	for ns, pfx := range nsPrefixes {
		pfxCopy := pfx
		nsb := &netipx.IPSetBuilder{}
		network, broadcast := util.GetIPPrefixEndpoints(pfxCopy)
		nsb.Add(network)
		nsb.Add(broadcast)
		ret.nsUsed[ns] = nsb
		ret.nsPrev[ns] = network
	}

	// Fetch all nodes from the database to properly initialize namespace prev pointers.
	var nodes []types.Node
	if db != nil {
		err := db.Read(func(rx *gorm.DB) error {
			return rx.Preload("User").Find(&nodes).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading nodes from database: %w", err)
		}
	}

	// Track the highest IP allocated per namespace to set nsPrev correctly.
	nsMaxIP := make(map[string]netip.Addr)

	// Fetch all the IP Addresses currently handed out from the Database
	// and add them to the used IP set.
	for _, node := range nodes {
		// Process IPv4
		if node.IPv4 != nil {
			addr := *node.IPv4

			// Add to global used set.
			ips.Add(addr)

			// Determine namespace for this node
			namespace := ""
			if node.User != nil {
				namespace = node.User.Name
			}

			// Add to namespace pool and track max IP if this namespace has a dedicated prefix
			if namespace != "" {
				if nsPfx, ok := nsPrefixes[namespace]; ok {
					if nsPfx.Contains(addr) {
						nsb := ret.nsUsed[namespace]
						nsb.Add(addr)

						// Track the highest IP in this namespace
						if maxIP, exists := nsMaxIP[namespace]; !exists || addr.Compare(maxIP) > 0 {
							nsMaxIP[namespace] = addr
						}
					}
				}
			}

			// Add to all namespace pools to prevent cross-namespace collisions
			for ns, nsb := range ret.nsUsed {
				nsb.Add(addr)
			}
		}

		// Process IPv6
		if node.IPv6 != nil {
			addr := *node.IPv6
			ips.Add(addr)

			// IPv6 doesn't use namespace-specific prefixes, but still add to all namespace pools
			for _, nsb := range ret.nsUsed {
				nsb.Add(addr)
			}
		}
	}

	// Update nsPrev to the highest allocated IP in each namespace
	for ns, maxIP := range nsMaxIP {
		ret.nsPrev[ns] = maxIP
		log.Debug().
			Str("namespace", ns).
			Str("max_ip", maxIP.String()).
			Msg("initialized namespace prev pointer from existing allocations")
	}

	// Build the initial IPSet to validate that we can use it.
	_, err := ips.IPSet()
	if err != nil {
		return nil, fmt.Errorf(
			"building initial IP Set: %w",
			err,
		)
	}

	ret.usedIPs = ips

	return &ret, nil
}

func (i *IPAllocator) Next() (*netip.Addr, *netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	var (
		err  error
		ret4 *netip.Addr
		ret6 *netip.Addr
	)

	if i.prefix4 != nil {
		ret4, err = i.next(i.prev4, i.prefix4)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv4 address: %w", err)
		}

		i.prev4 = *ret4
	}

	if i.prefix6 != nil {
		ret6, err = i.next(i.prev6, i.prefix6)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv6 address: %w", err)
		}

		i.prev6 = *ret6
	}

	return ret4, ret6, nil
}

// NextForNamespace allocates an IPv4 address for the given namespace.
// If the namespace has a dedicated prefix configured (via PrefixesByNamespace),
// the IP is drawn from that pool. Otherwise it falls back to the global prefix4.
// IPv6 is always allocated from the global prefix6 (namespace-specific v6 is not supported).
func (i *IPAllocator) NextForNamespace(namespace string) (*netip.Addr, *netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	var (
		err  error
		ret4 *netip.Addr
		ret6 *netip.Addr
	)

	// Determine which IPv4 prefix to use for this namespace.
	if nsPfx, ok := i.nsPrefixes[namespace]; ok {
		nsb := i.nsUsed[namespace]
		prev := i.nsPrev[namespace]

		ret4, err = i.nextFromBuilder(prev, &nsPfx, nsb)
		if err != nil {
			// Namespace-specific prefix is exhausted, fall back to global prefix
			log.Warn().
				Str("namespace", namespace).
				Str("prefix", nsPfx.String()).
				Err(err).
				Msg("namespace-specific prefix exhausted, falling back to global prefix")

			if i.prefix4 != nil {
				ret4, err = i.next(i.prev4, i.prefix4)
				if err != nil {
					return nil, nil, fmt.Errorf("allocating IPv4 address from global prefix after namespace exhaustion: %w", err)
				}

				i.prev4 = *ret4

				log.Info().
					Str("namespace", namespace).
					Str("prefix", i.prefix4.String()).
					Str("ip", ret4.String()).
					Msg("allocated IP from global prefix (namespace prefix exhausted)")
			} else {
				return nil, nil, fmt.Errorf("allocating IPv4 for namespace %q: namespace prefix exhausted and no global prefix configured: %w", namespace, err)
			}
		} else {
			i.nsPrev[namespace] = *ret4

			log.Debug().
				Str("namespace", namespace).
				Str("prefix", nsPfx.String()).
				Str("ip", ret4.String()).
				Msg("allocated IP from namespace-specific prefix")
		}
	} else if i.prefix4 != nil {
		// Fallback to global prefix.
		ret4, err = i.next(i.prev4, i.prefix4)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv4 address: %w", err)
		}

		i.prev4 = *ret4

		log.Debug().
			Str("namespace", namespace).
			Str("prefix", i.prefix4.String()).
			Str("ip", ret4.String()).
			Msg("allocated IP from global prefix (namespace not configured)")
	}

	// IPv6 always uses the global prefix6.
	if i.prefix6 != nil {
		ret6, err = i.next(i.prev6, i.prefix6)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv6 address: %w", err)
		}

		i.prev6 = *ret6
	}

	return ret4, ret6, nil
}

var ErrCouldNotAllocateIP = errors.New("failed to allocate IP")

func (i *IPAllocator) nextLocked(prev netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.next(prev, prefix)
}

// nextFromBuilder is like next but uses a caller-supplied IPSetBuilder
// instead of the global i.usedIPs. Used for per-namespace prefix pools.
func (i *IPAllocator) nextFromBuilder(prev netip.Addr, prefix *netip.Prefix, builder *netipx.IPSetBuilder) (*netip.Addr, error) {
	var (
		err error
		ip  netip.Addr
	)

	switch i.strategy {
	case types.IPAllocationStrategySequential:
		ip = prev.Next()
	case types.IPAllocationStrategyRandom:
		ip, err = randomNext(*prefix)
		if err != nil {
			return nil, fmt.Errorf("getting random IP: %w", err)
		}
	}

	set, err := builder.IPSet()
	if err != nil {
		return nil, err
	}

	startIP := ip
	wrappedAround := false

	for {
		if !prefix.Contains(ip) {
			// If we've reached the end of the prefix and haven't wrapped around yet,
			// start from the beginning to find holes left by deleted nodes
			if !wrappedAround && i.strategy == types.IPAllocationStrategySequential {
				wrappedAround = true
				ip = prefix.Addr().Next() // Start from first usable IP in prefix
				log.Debug().
					Str("prefix", prefix.String()).
					Str("restart_ip", ip.String()).
					Msg("reached end of prefix, wrapping around to find freed IPs")
				continue
			}
			return nil, ErrCouldNotAllocateIP
		}

		// Prevent infinite loop: if we've wrapped around and reached the starting IP again
		if wrappedAround && ip.Compare(startIP) >= 0 {
			return nil, ErrCouldNotAllocateIP
		}

		if set.Contains(ip) || isTailscaleReservedIP(ip) {
			switch i.strategy {
			case types.IPAllocationStrategySequential:
				ip = ip.Next()
			case types.IPAllocationStrategyRandom:
				ip, err = randomNext(*prefix)
				if err != nil {
					return nil, fmt.Errorf("getting random IP: %w", err)
				}
			}

			continue
		}

		builder.Add(ip)
		// Also mark in global usedIPs to prevent cross-namespace collisions.
		i.usedIPs.Add(ip)

		return &ip, nil
	}
}

func (i *IPAllocator) next(prev netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	var (
		err error
		ip  netip.Addr
	)

	switch i.strategy {
	case types.IPAllocationStrategySequential:
		// Get the first IP in our prefix
		ip = prev.Next()
	case types.IPAllocationStrategyRandom:
		ip, err = randomNext(*prefix)
		if err != nil {
			return nil, fmt.Errorf("getting random IP: %w", err)
		}
	}

	// TODO(kradalby): maybe this can be done less often.
	set, err := i.usedIPs.IPSet()
	if err != nil {
		return nil, err
	}

	for {
		if !prefix.Contains(ip) {
			return nil, ErrCouldNotAllocateIP
		}

		// Check if the IP has already been allocated
		// or if it is a IP reserved by Tailscale.
		if set.Contains(ip) || isTailscaleReservedIP(ip) {
			switch i.strategy {
			case types.IPAllocationStrategySequential:
				ip = ip.Next()
			case types.IPAllocationStrategyRandom:
				ip, err = randomNext(*prefix)
				if err != nil {
					return nil, fmt.Errorf("getting random IP: %w", err)
				}
			}

			continue
		}

		i.usedIPs.Add(ip)

		return &ip, nil
	}
}

func randomNext(pfx netip.Prefix) (netip.Addr, error) {
	rang := netipx.RangeOfPrefix(pfx)
	fromIP, toIP := rang.From(), rang.To()

	var from, to big.Int

	from.SetBytes(fromIP.AsSlice())
	to.SetBytes(toIP.AsSlice())

	// Find the max, this is how we can do "random range",
	// get the "max" as 0 -> to - from and then add back from
	// after.
	tempMax := big.NewInt(0).Sub(&to, &from)

	out, err := rand.Int(rand.Reader, tempMax)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("generating random IP: %w", err)
	}

	valInRange := big.NewInt(0).Add(&from, out)

	ip, ok := netip.AddrFromSlice(valInRange.Bytes())
	if !ok {
		return netip.Addr{}, errGeneratedIPBytesInvalid
	}

	if !pfx.Contains(ip) {
		return netip.Addr{}, fmt.Errorf(
			"%w: ip(%s) not in prefix(%s)",
			errGeneratedIPNotInPrefix,
			ip.String(),
			pfx.String(),
		)
	}

	return ip, nil
}

func isTailscaleReservedIP(ip netip.Addr) bool {
	return tsaddr.ChromeOSVMRange().Contains(ip) ||
		tsaddr.TailscaleServiceIP() == ip ||
		tsaddr.TailscaleServiceIPv6() == ip
}

// BackfillNodeIPs will take a database transaction, and
// iterate through all of the current nodes in headscale
// and ensure it has IP addresses according to the current
// configuration.
// This means that if both IPv4 and IPv6 is set in the
// config, and some nodes are missing that type of IP,
// it will be added.
// If a prefix type has been removed (IPv4 or IPv6), it
// will remove the IPs in that family from the node.
func (db *HSDatabase) BackfillNodeIPs(i *IPAllocator) ([]string, error) {
	var (
		err error
		ret []string
	)

	err = db.Write(func(tx *gorm.DB) error {
		if i == nil {
			return fmt.Errorf("backfilling IPs: %w", errIPAllocatorNil)
		}

		log.Trace().Caller().Msgf("starting to backfill IPs")

		nodes, err := ListNodes(tx)
		if err != nil {
			return fmt.Errorf("listing nodes to backfill IPs: %w", err)
		}

		for _, node := range nodes {
			log.Trace().Caller().EmbedObject(node).Msg("ip backfill check started because node found in database")

			// Determine the namespace name for this node (used for per-namespace prefix lookup).
			namespace := ""
			if node.User != nil {
				namespace = node.User.Name
			}

			changed := false
			// IPv4 prefix is set, but node ip is missing, alloc
			if (i.prefix4 != nil || len(i.nsPrefixes) > 0) && node.IPv4 == nil {
				ret4, _, err := i.NextForNamespace(namespace)
				if err != nil {
					return fmt.Errorf("allocating IPv4 for node(%d): %w", node.ID, err)
				}

				node.IPv4 = ret4
				changed = true

				ret = append(ret, fmt.Sprintf("assigned IPv4 %q to Node(%d) %q (namespace %q)", ret4.String(), node.ID, node.Hostname, namespace))
			}

			// IPv6 prefix is set, but node ip is missing, alloc
			if i.prefix6 != nil && node.IPv6 == nil {
				_, ret6, err := i.NextForNamespace(namespace)
				if err != nil {
					return fmt.Errorf("allocating IPv6 for node(%d): %w", node.ID, err)
				}

				node.IPv6 = ret6
				changed = true

				ret = append(ret, fmt.Sprintf("assigned IPv6 %q to Node(%d) %q", ret6.String(), node.ID, node.Hostname))
			}

			// IPv4 prefix is not set, but node has IP, remove
			if i.prefix4 == nil && len(i.nsPrefixes) == 0 && node.IPv4 != nil {
				ret = append(ret, fmt.Sprintf("removing IPv4 %q from Node(%d) %q", node.IPv4.String(), node.ID, node.Hostname))
				node.IPv4 = nil
				changed = true
			}

			// IPv6 prefix is not set, but node has IP, remove
			if i.prefix6 == nil && node.IPv6 != nil {
				ret = append(ret, fmt.Sprintf("removing IPv6 %q from Node(%d) %q", node.IPv6.String(), node.ID, node.Hostname))
				node.IPv6 = nil
				changed = true
			}

			if changed {
				// Use Updates() with Select() to only update IP fields, avoiding overwriting
				// other fields like Expiry. We need Select() because Updates() alone skips
				// zero values, but we DO want to update IPv4/IPv6 to nil when removing them.
				// See issue #2862.
				err := tx.Model(node).Select("ipv4", "ipv6").Updates(node).Error
				if err != nil {
					return fmt.Errorf("saving node(%d) after adding IPs: %w", node.ID, err)
				}
			}
		}

		return nil
	})

	return ret, err
}

func (i *IPAllocator) FreeIPs(ips []netip.Addr) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for _, ip := range ips {
		// Remove from global used set
		i.usedIPs.Remove(ip)

		// Also remove from all namespace-specific used sets
		for ns, nsb := range i.nsUsed {
			nsb.Remove(ip)
			log.Debug().
				Str("namespace", ns).
				Str("ip", ip.String()).
				Msg("freed IP from namespace pool")
		}
	}
}
