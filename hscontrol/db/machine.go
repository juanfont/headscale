package db

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	MachineGivenNameHashLength = 8
	MachineGivenNameTrimSize   = 2
	MaxHostnameLength          = 255
	DefaultKeyExpireTime       = 60 * time.Minute
)

var (
	ErrMachineNotFound                  = errors.New("machine not found")
	ErrMachineRouteIsNotAvailable       = errors.New("route is not available on machine")
	ErrMachineNotFoundRegistrationCache = errors.New(
		"machine not found in registration cache",
	)
	ErrCouldNotConvertMachineInterface = errors.New("failed to convert machine interface")
	ErrHostnameTooLong                 = errors.New("hostname too long")
	ErrDifferentRegisteredUser         = errors.New(
		"machine was previously registered with a different user",
	)
)

// filterMachinesByACL wrapper function to not have devs pass around locks and maps
// related to the application outside of tests.
func (hsdb *HSDatabase) filterMachinesByACL(
	aclRules []tailcfg.FilterRule,
	currentMachine *types.Machine, peers types.Machines,
) types.Machines {
	return policy.FilterMachinesByACL(currentMachine, peers, aclRules)
}

func (hsdb *HSDatabase) ListPeers(machine *types.Machine) (types.Machines, error) {
	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msg("Finding direct peers")

	machines := types.Machines{}
	if err := hsdb.db.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where("node_key <> ?",
		machine.NodeKey).Find(&machines).Error; err != nil {
		log.Error().Err(err).Msg("Error accessing db")

		return types.Machines{}, err
	}

	sort.Slice(machines, func(i, j int) bool { return machines[i].ID < machines[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msgf("Found peers: %s", machines.String())

	return machines, nil
}

func (hsdb *HSDatabase) getPeers(
	aclRules []tailcfg.FilterRule,
	machine *types.Machine,
) (types.Machines, error) {
	var peers types.Machines
	var err error

	// If ACLs rules are defined, filter visible host list with the ACLs
	// else use the classic user scope
	if len(aclRules) > 0 {
		var machines []types.Machine
		machines, err = hsdb.ListMachines()
		if err != nil {
			log.Error().Err(err).Msg("Error retrieving list of machines")

			return types.Machines{}, err
		}
		peers = hsdb.filterMachinesByACL(aclRules, machine, machines)
	} else {
		peers, err = hsdb.ListPeers(machine)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot fetch peers")

			return types.Machines{}, err
		}
	}

	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Caller().
		Str("self", machine.Hostname).
		Str("peers", peers.String()).
		Msg("Peers returned to caller")

	return peers, nil
}

func (hsdb *HSDatabase) GetValidPeers(
	aclRules []tailcfg.FilterRule,
	machine *types.Machine,
) (types.Machines, error) {
	validPeers := make(types.Machines, 0)

	peers, err := hsdb.getPeers(aclRules, machine)
	if err != nil {
		return types.Machines{}, err
	}

	for _, peer := range peers {
		if !peer.IsExpired() {
			validPeers = append(validPeers, peer)
		}
	}

	return validPeers, nil
}

func (hsdb *HSDatabase) ListMachines() ([]types.Machine, error) {
	machines := []types.Machine{}
	if err := hsdb.db.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

func (hsdb *HSDatabase) ListMachinesByGivenName(givenName string) (types.Machines, error) {
	machines := types.Machines{}
	if err := hsdb.db.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where("given_name = ?", givenName).Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

// GetMachine finds a Machine by name and user and returns the Machine struct.
func (hsdb *HSDatabase) GetMachine(user string, name string) (*types.Machine, error) {
	machines, err := hsdb.ListMachinesByUser(user)
	if err != nil {
		return nil, err
	}

	for _, m := range machines {
		if m.Hostname == name {
			return &m, nil
		}
	}

	return nil, ErrMachineNotFound
}

// GetMachineByGivenName finds a Machine by given name and user and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByGivenName(
	user string,
	givenName string,
) (*types.Machine, error) {
	machines, err := hsdb.ListMachinesByUser(user)
	if err != nil {
		return nil, err
	}

	for _, m := range machines {
		if m.GivenName == givenName {
			return &m, nil
		}
	}

	return nil, ErrMachineNotFound
}

// GetMachineByID finds a Machine by ID and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByID(id uint64) (*types.Machine, error) {
	m := types.Machine{}
	if result := hsdb.db.Preload("AuthKey").Preload("User").Find(&types.Machine{ID: id}).First(&m); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetMachineByMachineKey finds a Machine by its MachineKey and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByMachineKey(
	machineKey key.MachinePublic,
) (*types.Machine, error) {
	m := types.Machine{}
	if result := hsdb.db.Preload("AuthKey").Preload("User").First(&m, "machine_key = ?", util.MachinePublicKeyStripPrefix(machineKey)); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetMachineByNodeKey finds a Machine by its current NodeKey.
func (hsdb *HSDatabase) GetMachineByNodeKey(
	nodeKey key.NodePublic,
) (*types.Machine, error) {
	machine := types.Machine{}
	if result := hsdb.db.Preload("AuthKey").Preload("User").First(&machine, "node_key = ?",
		util.NodePublicKeyStripPrefix(nodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &machine, nil
}

// GetMachineByAnyNodeKey finds a Machine by its MachineKey, its current NodeKey or the old one, and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByAnyKey(
	machineKey key.MachinePublic, nodeKey key.NodePublic, oldNodeKey key.NodePublic,
) (*types.Machine, error) {
	machine := types.Machine{}
	if result := hsdb.db.Preload("AuthKey").Preload("User").First(&machine, "machine_key = ? OR node_key = ? OR node_key = ?",
		util.MachinePublicKeyStripPrefix(machineKey),
		util.NodePublicKeyStripPrefix(nodeKey),
		util.NodePublicKeyStripPrefix(oldNodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &machine, nil
}

// TODO(kradalby): rename this, it sounds like a mix of getting and setting to db
// UpdateMachineFromDatabase takes a Machine struct pointer (typically already loaded from database
// and updates it with the latest data from the database.
func (hsdb *HSDatabase) UpdateMachineFromDatabase(machine *types.Machine) error {
	if result := hsdb.db.Find(machine).First(&machine); result.Error != nil {
		return result.Error
	}

	return nil
}

// SetTags takes a Machine struct pointer and update the forced tags.
func (hsdb *HSDatabase) SetTags(
	machine *types.Machine,
	tags []string,
) error {
	newTags := []string{}
	for _, tag := range tags {
		if !util.StringOrPrefixListContains(newTags, tag) {
			newTags = append(newTags, tag)
		}
	}
	machine.ForcedTags = newTags

	hsdb.notifyPolicyChan <- struct{}{}
	hsdb.notifyStateChange()

	if err := hsdb.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to update tags for machine in the database: %w", err)
	}

	return nil
}

// ExpireMachine takes a Machine struct and sets the expire field to now.
func (hsdb *HSDatabase) ExpireMachine(machine *types.Machine) error {
	now := time.Now()
	machine.Expiry = &now

	hsdb.notifyStateChange()

	if err := hsdb.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to expire machine in the database: %w", err)
	}

	return nil
}

// RenameMachine takes a Machine struct and a new GivenName for the machines
// and renames it.
func (hsdb *HSDatabase) RenameMachine(machine *types.Machine, newName string) error {
	err := util.CheckForFQDNRules(
		newName,
	)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "RenameMachine").
			Str("machine", machine.Hostname).
			Str("newName", newName).
			Err(err)

		return err
	}
	machine.GivenName = newName

	hsdb.notifyStateChange()

	if err := hsdb.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to rename machine in the database: %w", err)
	}

	return nil
}

// RefreshMachine takes a Machine struct and  a new expiry time.
func (hsdb *HSDatabase) RefreshMachine(machine *types.Machine, expiry time.Time) error {
	now := time.Now()

	machine.LastSuccessfulUpdate = &now
	machine.Expiry = &expiry

	hsdb.notifyStateChange()

	if err := hsdb.db.Save(machine).Error; err != nil {
		return fmt.Errorf(
			"failed to refresh machine (update expiration) in the database: %w",
			err,
		)
	}

	return nil
}

// DeleteMachine softs deletes a Machine from the database.
func (hsdb *HSDatabase) DeleteMachine(machine *types.Machine) error {
	err := hsdb.DeleteMachineRoutes(machine)
	if err != nil {
		return err
	}

	if err := hsdb.db.Delete(&machine).Error; err != nil {
		return err
	}

	return nil
}

func (hsdb *HSDatabase) TouchMachine(machine *types.Machine) error {
	return hsdb.db.Updates(types.Machine{
		ID:                   machine.ID,
		LastSeen:             machine.LastSeen,
		LastSuccessfulUpdate: machine.LastSuccessfulUpdate,
		Expiry:               machine.Expiry,
	}).Error
}

// HardDeleteMachine hard deletes a Machine from the database.
func (hsdb *HSDatabase) HardDeleteMachine(machine *types.Machine) error {
	err := hsdb.DeleteMachineRoutes(machine)
	if err != nil {
		return err
	}

	if err := hsdb.db.Unscoped().Delete(&machine).Error; err != nil {
		return err
	}

	return nil
}

func (hsdb *HSDatabase) IsOutdated(machine *types.Machine, lastChange time.Time) bool {
	if err := hsdb.UpdateMachineFromDatabase(machine); err != nil {
		// It does not seem meaningful to propagate this error as the end result
		// will have to be that the machine has to be considered outdated.
		return true
	}

	// Get the last update from all headscale users to compare with our nodes
	// last update.
	// TODO(kradalby): Only request updates from users where we can talk to nodes
	// This would mostly be for a bit of performance, and can be calculated based on
	// ACLs.
	lastUpdate := machine.CreatedAt
	if machine.LastSuccessfulUpdate != nil {
		lastUpdate = *machine.LastSuccessfulUpdate
	}
	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Time("last_successful_update", lastChange).
		Time("last_state_change", lastUpdate).
		Msgf("Checking if %s is missing updates", machine.Hostname)

	return lastUpdate.Before(lastChange)
}

func (hsdb *HSDatabase) RegisterMachineFromAuthCallback(
	cache *cache.Cache,
	nodeKeyStr string,
	userName string,
	machineExpiry *time.Time,
	registrationMethod string,
) (*types.Machine, error) {
	nodeKey := key.NodePublic{}
	err := nodeKey.UnmarshalText([]byte(nodeKeyStr))
	if err != nil {
		return nil, err
	}

	log.Debug().
		Str("nodeKey", nodeKey.ShortString()).
		Str("userName", userName).
		Str("registrationMethod", registrationMethod).
		Str("expiresAt", fmt.Sprintf("%v", machineExpiry)).
		Msg("Registering machine from API/CLI or auth callback")

	if machineInterface, ok := cache.Get(util.NodePublicKeyStripPrefix(nodeKey)); ok {
		if registrationMachine, ok := machineInterface.(types.Machine); ok {
			user, err := hsdb.GetUser(userName)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to find user in register machine from auth callback, %w",
					err,
				)
			}

			// Registration of expired machine with different user
			if registrationMachine.ID != 0 &&
				registrationMachine.UserID != user.ID {
				return nil, ErrDifferentRegisteredUser
			}

			registrationMachine.UserID = user.ID
			registrationMachine.RegisterMethod = registrationMethod
			expiryTime := time.Now().Add(DefaultKeyExpireTime)
			if machineExpiry != nil {
				registrationMachine.Expiry = machineExpiry
			} else {
				registrationMachine.Expiry = &expiryTime
			}

			machine, err := hsdb.RegisterMachine(
				registrationMachine,
			)

			if err == nil {
				cache.Delete(nodeKeyStr)
			}

			return machine, err
		} else {
			return nil, ErrCouldNotConvertMachineInterface
		}
	}

	return nil, ErrMachineNotFoundRegistrationCache
}

// RegisterMachine is executed from the CLI to register a new Machine using its MachineKey.
func (hsdb *HSDatabase) RegisterMachine(machine types.Machine,
) (*types.Machine, error) {
	log.Debug().
		Str("machine", machine.Hostname).
		Str("machine_key", machine.MachineKey).
		Str("node_key", machine.NodeKey).
		Str("user", machine.User.Name).
		Msg("Registering machine")

	// If the machine exists and we had already IPs for it, we just save it
	// so we store the machine.Expire and machine.Nodekey that has been set when
	// adding it to the registrationCache
	if len(machine.IPAddresses) > 0 {
		if err := hsdb.db.Save(&machine).Error; err != nil {
			return nil, fmt.Errorf("failed register existing machine in the database: %w", err)
		}

		log.Trace().
			Caller().
			Str("machine", machine.Hostname).
			Str("machine_key", machine.MachineKey).
			Str("node_key", machine.NodeKey).
			Str("user", machine.User.Name).
			Msg("Machine authorized again")

		return &machine, nil
	}

	hsdb.ipAllocationMutex.Lock()
	defer hsdb.ipAllocationMutex.Unlock()

	ips, err := hsdb.getAvailableIPs()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Hostname).
			Msg("Could not find IP for the new machine")

		return nil, err
	}

	machine.IPAddresses = ips

	if err := hsdb.db.Save(&machine).Error; err != nil {
		return nil, fmt.Errorf("failed register(save) machine in the database: %w", err)
	}

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Str("ip", strings.Join(ips.ToStringSlice(), ",")).
		Msg("Machine registered with the database")

	return &machine, nil
}

// MachineSetNodeKey sets the node key of a machine and saves it to the database.
func (hsdb *HSDatabase) MachineSetNodeKey(machine *types.Machine, nodeKey key.NodePublic) error {
	machine.NodeKey = util.NodePublicKeyStripPrefix(nodeKey)

	if err := hsdb.db.Save(machine).Error; err != nil {
		return err
	}

	return nil
}

// MachineSetMachineKey sets the machine key of a machine and saves it to the database.
func (hsdb *HSDatabase) MachineSetMachineKey(
	machine *types.Machine,
	nodeKey key.MachinePublic,
) error {
	machine.MachineKey = util.MachinePublicKeyStripPrefix(nodeKey)

	if err := hsdb.db.Save(machine).Error; err != nil {
		return err
	}

	return nil
}

// MachineSave saves a machine object to the database, prefer to use a specific save method rather
// than this. It is intended to be used when we are changing or.
func (hsdb *HSDatabase) MachineSave(machine *types.Machine) error {
	if err := hsdb.db.Save(machine).Error; err != nil {
		return err
	}

	return nil
}

// GetAdvertisedRoutes returns the routes that are be advertised by the given machine.
func (hsdb *HSDatabase) GetAdvertisedRoutes(machine *types.Machine) ([]netip.Prefix, error) {
	routes := types.Routes{}

	err := hsdb.db.
		Preload("Machine").
		Where("machine_id = ? AND advertised = ?", machine.ID, true).Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Hostname).
			Msg("Could not get advertised routes for machine")

		return nil, err
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

// GetEnabledRoutes returns the routes that are enabled for the machine.
func (hsdb *HSDatabase) GetEnabledRoutes(machine *types.Machine) ([]netip.Prefix, error) {
	routes := types.Routes{}

	err := hsdb.db.
		Preload("Machine").
		Where("machine_id = ? AND advertised = ? AND enabled = ?", machine.ID, true, true).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Hostname).
			Msg("Could not get enabled routes for machine")

		return nil, err
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

func (hsdb *HSDatabase) IsRoutesEnabled(machine *types.Machine, routeStr string) bool {
	route, err := netip.ParsePrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes, err := hsdb.GetEnabledRoutes(machine)
	if err != nil {
		log.Error().Err(err).Msg("Could not get enabled routes")

		return false
	}

	for _, enabledRoute := range enabledRoutes {
		if route == enabledRoute {
			return true
		}
	}

	return false
}

// enableRoutes enables new routes based on a list of new routes.
func (hsdb *HSDatabase) enableRoutes(machine *types.Machine, routeStrs ...string) error {
	newRoutes := make([]netip.Prefix, len(routeStrs))
	for index, routeStr := range routeStrs {
		route, err := netip.ParsePrefix(routeStr)
		if err != nil {
			return err
		}

		newRoutes[index] = route
	}

	advertisedRoutes, err := hsdb.GetAdvertisedRoutes(machine)
	if err != nil {
		return err
	}

	for _, newRoute := range newRoutes {
		if !util.StringOrPrefixListContains(advertisedRoutes, newRoute) {
			return fmt.Errorf(
				"route (%s) is not available on node %s: %w",
				machine.Hostname,
				newRoute, ErrMachineRouteIsNotAvailable,
			)
		}
	}

	// Separate loop so we don't leave things in a half-updated state
	for _, prefix := range newRoutes {
		route := types.Route{}
		err := hsdb.db.Preload("Machine").
			Where("machine_id = ? AND prefix = ?", machine.ID, types.IPPrefix(prefix)).
			First(&route).Error
		if err == nil {
			route.Enabled = true

			// Mark already as primary if there is only this node offering this subnet
			// (and is not an exit route)
			if !route.IsExitRoute() {
				route.IsPrimary = hsdb.isUniquePrefix(route)
			}

			err = hsdb.db.Save(&route).Error
			if err != nil {
				return fmt.Errorf("failed to enable route: %w", err)
			}
		} else {
			return fmt.Errorf("failed to find route: %w", err)
		}
	}

	hsdb.notifyStateChange()

	return nil
}

func (hsdb *HSDatabase) generateGivenName(suppliedName string, randomSuffix bool) (string, error) {
	normalizedHostname, err := util.NormalizeToFQDNRules(
		suppliedName,
		hsdb.stripEmailDomain,
	)
	if err != nil {
		return "", err
	}

	if randomSuffix {
		// Trim if a hostname will be longer than 63 chars after adding the hash.
		trimmedHostnameLength := util.LabelHostnameLength - MachineGivenNameHashLength - MachineGivenNameTrimSize
		if len(normalizedHostname) > trimmedHostnameLength {
			normalizedHostname = normalizedHostname[:trimmedHostnameLength]
		}

		suffix, err := util.GenerateRandomStringDNSSafe(MachineGivenNameHashLength)
		if err != nil {
			return "", err
		}

		normalizedHostname += "-" + suffix
	}

	return normalizedHostname, nil
}

func (hsdb *HSDatabase) GenerateGivenName(machineKey string, suppliedName string) (string, error) {
	givenName, err := hsdb.generateGivenName(suppliedName, false)
	if err != nil {
		return "", err
	}

	// Tailscale rules (may differ) https://tailscale.com/kb/1098/machine-names/
	machines, err := hsdb.ListMachinesByGivenName(givenName)
	if err != nil {
		return "", err
	}

	for _, machine := range machines {
		if machine.MachineKey != machineKey && machine.GivenName == givenName {
			postfixedName, err := hsdb.generateGivenName(suppliedName, true)
			if err != nil {
				return "", err
			}

			givenName = postfixedName
		}
	}

	return givenName, nil
}

func (hsdb *HSDatabase) ExpireEphemeralMachines(inactivityThreshhold time.Duration) {
	users, err := hsdb.ListUsers()
	if err != nil {
		log.Error().Err(err).Msg("Error listing users")

		return
	}

	for _, user := range users {
		machines, err := hsdb.ListMachinesByUser(user.Name)
		if err != nil {
			log.Error().
				Err(err).
				Str("user", user.Name).
				Msg("Error listing machines in user")

			return
		}

		expiredFound := false
		for idx, machine := range machines {
			if machine.IsEphemeral() && machine.LastSeen != nil &&
				time.Now().
					After(machine.LastSeen.Add(inactivityThreshhold)) {
				expiredFound = true
				log.Info().
					Str("machine", machine.Hostname).
					Msg("Ephemeral client removed from database")

				err = hsdb.HardDeleteMachine(&machines[idx])
				if err != nil {
					log.Error().
						Err(err).
						Str("machine", machine.Hostname).
						Msg("🤮 Cannot delete ephemeral machine from the database")
				}
			}
		}

		if expiredFound {
			hsdb.notifyStateChange()
		}
	}
}

func (hsdb *HSDatabase) ExpireExpiredMachines(lastChange time.Time) {
	users, err := hsdb.ListUsers()
	if err != nil {
		log.Error().Err(err).Msg("Error listing users")

		return
	}

	for _, user := range users {
		machines, err := hsdb.ListMachinesByUser(user.Name)
		if err != nil {
			log.Error().
				Err(err).
				Str("user", user.Name).
				Msg("Error listing machines in user")

			return
		}

		expiredFound := false
		for index, machine := range machines {
			if machine.IsExpired() &&
				machine.Expiry.After(lastChange) {
				expiredFound = true

				err := hsdb.ExpireMachine(&machines[index])
				if err != nil {
					log.Error().
						Err(err).
						Str("machine", machine.Hostname).
						Str("name", machine.GivenName).
						Msg("🤮 Cannot expire machine")
				} else {
					log.Info().
						Str("machine", machine.Hostname).
						Str("name", machine.GivenName).
						Msg("Machine successfully expired")
				}
			}
		}

		if expiredFound {
			hsdb.notifyStateChange()
		}
	}
}

func (hsdb *HSDatabase) TailNodes(
	machines types.Machines,
	pol *policy.ACLPolicy,
	dnsConfig *tailcfg.DNSConfig,
) ([]*tailcfg.Node, error) {
	nodes := make([]*tailcfg.Node, len(machines))

	for index, machine := range machines {
		node, err := hsdb.TailNode(machine, pol, dnsConfig)
		if err != nil {
			return nil, err
		}

		nodes[index] = node
	}

	return nodes, nil
}

// TailNode converts a Machine into a Tailscale Node. includeRoutes is false for shared nodes
// as per the expected behaviour in the official SaaS.
func (hsdb *HSDatabase) TailNode(
	machine types.Machine,
	pol *policy.ACLPolicy,
	dnsConfig *tailcfg.DNSConfig,
) (*tailcfg.Node, error) {
	var nodeKey key.NodePublic
	err := nodeKey.UnmarshalText([]byte(util.NodePublicKeyEnsurePrefix(machine.NodeKey)))
	if err != nil {
		log.Trace().
			Caller().
			Str("node_key", machine.NodeKey).
			Msgf("Failed to parse node public key from hex")

		return nil, fmt.Errorf("failed to parse node public key: %w", err)
	}

	var machineKey key.MachinePublic
	// MachineKey is only used in the legacy protocol
	if machine.MachineKey != "" {
		err = machineKey.UnmarshalText(
			[]byte(util.MachinePublicKeyEnsurePrefix(machine.MachineKey)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse machine public key: %w", err)
		}
	}

	var discoKey key.DiscoPublic
	if machine.DiscoKey != "" {
		err := discoKey.UnmarshalText(
			[]byte(util.DiscoPublicKeyEnsurePrefix(machine.DiscoKey)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse disco public key: %w", err)
		}
	} else {
		discoKey = key.DiscoPublic{}
	}

	addrs := []netip.Prefix{}
	for _, machineAddress := range machine.IPAddresses {
		ip := netip.PrefixFrom(machineAddress, machineAddress.BitLen())
		addrs = append(addrs, ip)
	}

	allowedIPs := append(
		[]netip.Prefix{},
		addrs...) // we append the node own IP, as it is required by the clients

	primaryRoutes, err := hsdb.GetMachinePrimaryRoutes(&machine)
	if err != nil {
		return nil, err
	}
	primaryPrefixes := primaryRoutes.Prefixes()

	machineRoutes, err := hsdb.GetMachineRoutes(&machine)
	if err != nil {
		return nil, err
	}
	for _, route := range machineRoutes {
		if route.Enabled && (route.IsPrimary || route.IsExitRoute()) {
			allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix))
		}
	}

	var derp string
	if machine.HostInfo.NetInfo != nil {
		derp = fmt.Sprintf("127.3.3.40:%d", machine.HostInfo.NetInfo.PreferredDERP)
	} else {
		derp = "127.3.3.40:0" // Zero means disconnected or unknown.
	}

	var keyExpiry time.Time
	if machine.Expiry != nil {
		keyExpiry = *machine.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	var hostname string
	if dnsConfig != nil && dnsConfig.Proxied { // MagicDNS
		hostname = fmt.Sprintf(
			"%s.%s.%s",
			machine.GivenName,
			machine.User.Name,
			hsdb.baseDomain,
		)
		if len(hostname) > MaxHostnameLength {
			return nil, fmt.Errorf(
				"hostname %q is too long it cannot except 255 ASCII chars: %w",
				hostname,
				ErrHostnameTooLong,
			)
		}
	} else {
		hostname = machine.GivenName
	}

	hostInfo := machine.GetHostInfo()

	online := machine.IsOnline()

	tags, _ := pol.GetTagsOfMachine(machine, hsdb.stripEmailDomain)
	tags = lo.Uniq(append(tags, machine.ForcedTags...))

	node := tailcfg.Node{
		ID: tailcfg.NodeID(machine.ID), // this is the actual ID
		StableID: tailcfg.StableNodeID(
			strconv.FormatUint(machine.ID, util.Base10),
		), // in headscale, unlike tailcontrol server, IDs are permanent
		Name: hostname,

		User: tailcfg.UserID(machine.UserID),

		Key:       nodeKey,
		KeyExpiry: keyExpiry,

		Machine:    machineKey,
		DiscoKey:   discoKey,
		Addresses:  addrs,
		AllowedIPs: allowedIPs,
		Endpoints:  machine.Endpoints,
		DERP:       derp,
		Hostinfo:   hostInfo.View(),
		Created:    machine.CreatedAt,

		Tags: tags,

		PrimaryRoutes: primaryPrefixes,

		LastSeen:          machine.LastSeen,
		Online:            &online,
		KeepAlive:         true,
		MachineAuthorized: !machine.IsExpired(),

		Capabilities: []string{
			tailcfg.CapabilityFileSharing,
			tailcfg.CapabilityAdmin,
			tailcfg.CapabilitySSH,
		},
	}

	return &node, nil
}
