package db

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	MachineGivenNameHashLength = 8
	MachineGivenNameTrimSize   = 2
)

var (
	ErrMachineNotFound                  = errors.New("machine not found")
	ErrMachineRouteIsNotAvailable       = errors.New("route is not available on machine")
	ErrMachineNotFoundRegistrationCache = errors.New(
		"machine not found in registration cache",
	)
	ErrCouldNotConvertMachineInterface = errors.New("failed to convert machine interface")
	ErrDifferentRegisteredUser         = errors.New(
		"machine was previously registered with a different user",
	)
)

// ListPeers returns all peers of machine, regardless of any Policy or if the node is expired.
func (hsdb *HSDatabase) ListPeers(machine *types.Machine) (types.Machines, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listPeers(machine)
}

func (hsdb *HSDatabase) listPeers(machine *types.Machine) (types.Machines, error) {
	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msg("Finding direct peers")

	machines := types.Machines{}
	if err := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Where("node_key <> ?",
			machine.NodeKey).Find(&machines).Error; err != nil {
		return types.Machines{}, err
	}

	sort.Slice(machines, func(i, j int) bool { return machines[i].ID < machines[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msgf("Found peers: %s", machines.String())

	return machines, nil
}

func (hsdb *HSDatabase) ListMachines() ([]types.Machine, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listMachines()
}

func (hsdb *HSDatabase) listMachines() ([]types.Machine, error) {
	machines := []types.Machine{}
	if err := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

func (hsdb *HSDatabase) ListMachinesByGivenName(givenName string) (types.Machines, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listMachinesByGivenName(givenName)
}

func (hsdb *HSDatabase) listMachinesByGivenName(givenName string) (types.Machines, error) {
	machines := types.Machines{}
	if err := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Where("given_name = ?", givenName).Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

// GetMachine finds a Machine by name and user and returns the Machine struct.
func (hsdb *HSDatabase) GetMachine(user string, name string) (*types.Machine, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	machines, err := hsdb.ListMachinesByUser(user)
	if err != nil {
		return nil, err
	}

	for _, m := range machines {
		if m.Hostname == name {
			return m, nil
		}
	}

	return nil, ErrMachineNotFound
}

// GetMachineByGivenName finds a Machine by given name and user and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByGivenName(
	user string,
	givenName string,
) (*types.Machine, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	machine := types.Machine{}
	if err := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Where("given_name = ?", givenName).First(&machine).Error; err != nil {
		return nil, err
	}

	return nil, ErrMachineNotFound
}

// GetMachineByID finds a Machine by ID and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByID(id uint64) (*types.Machine, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	mach := types.Machine{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Find(&types.Machine{ID: id}).First(&mach); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

// GetMachineByMachineKey finds a Machine by its MachineKey and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByMachineKey(
	machineKey key.MachinePublic,
) (*types.Machine, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	mach := types.Machine{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&mach, "machine_key = ?", util.MachinePublicKeyStripPrefix(machineKey)); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

// GetMachineByNodeKey finds a Machine by its current NodeKey.
func (hsdb *HSDatabase) GetMachineByNodeKey(
	nodeKey key.NodePublic,
) (*types.Machine, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	machine := types.Machine{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&machine, "node_key = ?",
			util.NodePublicKeyStripPrefix(nodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &machine, nil
}

// GetMachineByAnyNodeKey finds a Machine by its MachineKey, its current NodeKey or the old one, and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByAnyKey(
	machineKey key.MachinePublic, nodeKey key.NodePublic, oldNodeKey key.NodePublic,
) (*types.Machine, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	machine := types.Machine{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&machine, "machine_key = ? OR node_key = ? OR node_key = ?",
			util.MachinePublicKeyStripPrefix(machineKey),
			util.NodePublicKeyStripPrefix(nodeKey),
			util.NodePublicKeyStripPrefix(oldNodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &machine, nil
}

func (hsdb *HSDatabase) MachineReloadFromDatabase(machine *types.Machine) error {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

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
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	newTags := []string{}
	for _, tag := range tags {
		if !util.StringOrPrefixListContains(newTags, tag) {
			newTags = append(newTags, tag)
		}
	}

	if err := hsdb.db.Model(machine).Updates(types.Machine{
		ForcedTags: newTags,
	}).Error; err != nil {
		return fmt.Errorf("failed to update tags for machine in the database: %w", err)
	}

	hsdb.notifier.NotifyWithIgnore(types.StateUpdate{
		Type:    types.StatePeerChanged,
		Changed: types.Machines{machine},
	}, machine.MachineKey)

	return nil
}

// RenameMachine takes a Machine struct and a new GivenName for the machines
// and renames it.
func (hsdb *HSDatabase) RenameMachine(machine *types.Machine, newName string) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	err := util.CheckForFQDNRules(
		newName,
	)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "RenameMachine").
			Str("machine", machine.Hostname).
			Str("newName", newName).
			Err(err).
			Msg("failed to rename machine")

		return err
	}
	machine.GivenName = newName

	if err := hsdb.db.Model(machine).Updates(types.Machine{
		GivenName: newName,
	}).Error; err != nil {
		return fmt.Errorf("failed to rename machine in the database: %w", err)
	}

	hsdb.notifier.NotifyWithIgnore(types.StateUpdate{
		Type:    types.StatePeerChanged,
		Changed: types.Machines{machine},
	}, machine.MachineKey)

	return nil
}

// MachineSetExpiry takes a Machine struct and  a new expiry time.
func (hsdb *HSDatabase) MachineSetExpiry(machine *types.Machine, expiry time.Time) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.machineSetExpiry(machine, expiry)
}

func (hsdb *HSDatabase) machineSetExpiry(machine *types.Machine, expiry time.Time) error {
	if err := hsdb.db.Model(machine).Updates(types.Machine{
		Expiry: &expiry,
	}).Error; err != nil {
		return fmt.Errorf(
			"failed to refresh machine (update expiration) in the database: %w",
			err,
		)
	}

	hsdb.notifier.NotifyWithIgnore(types.StateUpdate{
		Type:    types.StatePeerChanged,
		Changed: types.Machines{machine},
	}, machine.MachineKey)

	return nil
}

// DeleteMachine deletes a Machine from the database.
func (hsdb *HSDatabase) DeleteMachine(machine *types.Machine) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.deleteMachine(machine)
}

func (hsdb *HSDatabase) deleteMachine(machine *types.Machine) error {
	err := hsdb.deleteMachineRoutes(machine)
	if err != nil {
		return err
	}

	// Unscoped causes the machine to be fully removed from the database.
	if err := hsdb.db.Unscoped().Delete(&machine).Error; err != nil {
		return err
	}

	hsdb.notifier.NotifyAll(types.StateUpdate{
		Type:    types.StatePeerRemoved,
		Removed: []tailcfg.NodeID{tailcfg.NodeID(machine.ID)},
	})

	return nil
}

// UpdateLastSeen sets a machine's last seen field indicating that we
// have recently communicating with this machine.
// This is mostly used to indicate if a machine is online and is not
// extremely important to make sure is fully correct and to avoid
// holding up the hot path, does not contain any locks and isnt
// concurrency safe. But that should be ok.
func (hsdb *HSDatabase) UpdateLastSeen(machine *types.Machine) error {
	return hsdb.db.Model(machine).Updates(types.Machine{
		LastSeen: machine.LastSeen,
	}).Error
}

func (hsdb *HSDatabase) RegisterMachineFromAuthCallback(
	cache *cache.Cache,
	nodeKeyStr string,
	userName string,
	machineExpiry *time.Time,
	registrationMethod string,
) (*types.Machine, error) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

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
			user, err := hsdb.getUser(userName)
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

			if machineExpiry != nil {
				registrationMachine.Expiry = machineExpiry
			}

			machine, err := hsdb.registerMachine(
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
func (hsdb *HSDatabase) RegisterMachine(machine types.Machine) (*types.Machine, error) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.registerMachine(machine)
}

func (hsdb *HSDatabase) registerMachine(machine types.Machine) (*types.Machine, error) {
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
		Str("ip", strings.Join(ips.StringSlice(), ",")).
		Msg("Machine registered with the database")

	return &machine, nil
}

// MachineSetNodeKey sets the node key of a machine and saves it to the database.
func (hsdb *HSDatabase) MachineSetNodeKey(machine *types.Machine, nodeKey key.NodePublic) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if err := hsdb.db.Model(machine).Updates(types.Machine{
		NodeKey: util.NodePublicKeyStripPrefix(nodeKey),
	}).Error; err != nil {
		return err
	}

	return nil
}

// MachineSetMachineKey sets the machine key of a machine and saves it to the database.
func (hsdb *HSDatabase) MachineSetMachineKey(
	machine *types.Machine,
	machineKey key.MachinePublic,
) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if err := hsdb.db.Model(machine).Updates(types.Machine{
		MachineKey: util.MachinePublicKeyStripPrefix(machineKey),
	}).Error; err != nil {
		return err
	}

	return nil
}

// MachineSave saves a machine object to the database, prefer to use a specific save method rather
// than this. It is intended to be used when we are changing or.
func (hsdb *HSDatabase) MachineSave(machine *types.Machine) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if err := hsdb.db.Save(machine).Error; err != nil {
		return err
	}

	return nil
}

// GetAdvertisedRoutes returns the routes that are be advertised by the given machine.
func (hsdb *HSDatabase) GetAdvertisedRoutes(machine *types.Machine) ([]netip.Prefix, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getAdvertisedRoutes(machine)
}

func (hsdb *HSDatabase) getAdvertisedRoutes(machine *types.Machine) ([]netip.Prefix, error) {
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
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getEnabledRoutes(machine)
}

func (hsdb *HSDatabase) getEnabledRoutes(machine *types.Machine) ([]netip.Prefix, error) {
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
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	route, err := netip.ParsePrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes, err := hsdb.getEnabledRoutes(machine)
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

func OnlineMachineMap(peers types.Machines) map[tailcfg.NodeID]bool {
	ret := make(map[tailcfg.NodeID]bool)

	for _, peer := range peers {
		ret[tailcfg.NodeID(peer.ID)] = peer.IsOnline()
	}

	return ret
}

func (hsdb *HSDatabase) ListOnlineMachines(
	machine *types.Machine,
) (map[tailcfg.NodeID]bool, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	peers, err := hsdb.listPeers(machine)
	if err != nil {
		return nil, err
	}

	return OnlineMachineMap(peers), nil
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

	advertisedRoutes, err := hsdb.getAdvertisedRoutes(machine)
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

	hsdb.notifier.NotifyWithIgnore(types.StateUpdate{
		Type:    types.StatePeerChanged,
		Changed: types.Machines{machine},
	}, machine.MachineKey)

	return nil
}

func generateGivenName(suppliedName string, randomSuffix bool) (string, error) {
	normalizedHostname, err := util.NormalizeToFQDNRulesConfigFromViper(
		suppliedName,
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
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	givenName, err := generateGivenName(suppliedName, false)
	if err != nil {
		return "", err
	}

	// Tailscale rules (may differ) https://tailscale.com/kb/1098/machine-names/
	machines, err := hsdb.listMachinesByGivenName(givenName)
	if err != nil {
		return "", err
	}

	for _, machine := range machines {
		if machine.MachineKey != machineKey && machine.GivenName == givenName {
			postfixedName, err := generateGivenName(suppliedName, true)
			if err != nil {
				return "", err
			}

			givenName = postfixedName
		}
	}

	return givenName, nil
}

func (hsdb *HSDatabase) ExpireEphemeralMachines(inactivityThreshhold time.Duration) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	users, err := hsdb.listUsers()
	if err != nil {
		log.Error().Err(err).Msg("Error listing users")

		return
	}

	for _, user := range users {
		machines, err := hsdb.listMachinesByUser(user.Name)
		if err != nil {
			log.Error().
				Err(err).
				Str("user", user.Name).
				Msg("Error listing machines in user")

			return
		}

		expired := make([]tailcfg.NodeID, 0)
		for idx, machine := range machines {
			if machine.IsEphemeral() && machine.LastSeen != nil &&
				time.Now().
					After(machine.LastSeen.Add(inactivityThreshhold)) {
				expired = append(expired, tailcfg.NodeID(machine.ID))

				log.Info().
					Str("machine", machine.Hostname).
					Msg("Ephemeral client removed from database")

				err = hsdb.deleteMachine(machines[idx])
				if err != nil {
					log.Error().
						Err(err).
						Str("machine", machine.Hostname).
						Msg("🤮 Cannot delete ephemeral machine from the database")
				}
			}
		}

		if len(expired) > 0 {
			hsdb.notifier.NotifyAll(types.StateUpdate{
				Type:    types.StatePeerRemoved,
				Removed: expired,
			})
		}
	}
}

func (hsdb *HSDatabase) ExpireExpiredMachines(lastCheck time.Time) time.Time {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	// use the time of the start of the function to ensure we
	// dont miss some machines by returning it _after_ we have
	// checked everything.
	started := time.Now()

	users, err := hsdb.listUsers()
	if err != nil {
		log.Error().Err(err).Msg("Error listing users")

		return time.Unix(0, 0)
	}

	for _, user := range users {
		machines, err := hsdb.listMachinesByUser(user.Name)
		if err != nil {
			log.Error().
				Err(err).
				Str("user", user.Name).
				Msg("Error listing machines in user")

			return time.Unix(0, 0)
		}

		expired := make([]tailcfg.NodeID, 0)
		for index, machine := range machines {
			if machine.IsExpired() &&
				machine.Expiry.After(lastCheck) {
				expired = append(expired, tailcfg.NodeID(machine.ID))

				now := time.Now()
				err := hsdb.machineSetExpiry(machines[index], now)
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

		if len(expired) > 0 {
			hsdb.notifier.NotifyAll(types.StateUpdate{
				Type:    types.StatePeerRemoved,
				Removed: expired,
			})
		}
	}

	return started
}
