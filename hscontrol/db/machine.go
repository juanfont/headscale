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

// ListPeers returns all peers of machine, regardless of any Policy.
func (hsdb *HSDatabase) ListPeers(machine *types.Machine) (types.Machines, error) {
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
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Find(&types.Machine{ID: id}).First(&m); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetMachineByMachineKey finds a Machine by its MachineKey and returns the Machine struct.
func (hsdb *HSDatabase) GetMachineByMachineKey(
	machineKey key.MachinePublic,
) (*types.Machine, error) {
	m := types.Machine{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&m, "machine_key = ?", util.MachinePublicKeyStripPrefix(machineKey)); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetMachineByNodeKey finds a Machine by its current NodeKey.
func (hsdb *HSDatabase) GetMachineByNodeKey(
	nodeKey key.NodePublic,
) (*types.Machine, error) {
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

			if machineExpiry != nil {
				registrationMachine.Expiry = machineExpiry
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
		Str("ip", strings.Join(ips.StringSlice(), ",")).
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
