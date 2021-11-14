package headscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

const (
	errorNamespaceExists          = Error("Namespace already exists")
	errorNamespaceNotFound        = Error("Namespace not found")
	errorNamespaceNotEmptyOfNodes = Error("Namespace not empty: node(s) found")
)

// Namespace is the way Headscale implements the concept of users in Tailscale
//
// At the end of the day, users in Tailscale are some kind of 'bubbles' or namespaces
// that contain our machines.
type Namespace struct {
	gorm.Model
	Name string `gorm:"unique"`
}

// CreateNamespace creates a new Namespace. Returns error if could not be created
// or another namespace already exists.
func (h *Headscale) CreateNamespace(name string) (*Namespace, error) {
	n := Namespace{}
	if err := h.db.Where("name = ?", name).First(&n).Error; err == nil {
		return nil, errorNamespaceExists
	}
	n.Name = name
	if err := h.db.Create(&n).Error; err != nil {
		log.Error().
			Str("func", "CreateNamespace").
			Err(err).
			Msg("Could not create row")
		return nil, err
	}
	return &n, nil
}

// DestroyNamespace destroys a Namespace. Returns error if the Namespace does
// not exist or if there are machines associated with it.
func (h *Headscale) DestroyNamespace(name string) error {
	n, err := h.GetNamespace(name)
	if err != nil {
		return errorNamespaceNotFound
	}

	m, err := h.ListMachinesInNamespace(name)
	if err != nil {
		return err
	}
	if len(m) > 0 {
		return errorNamespaceNotEmptyOfNodes
	}

	keys, err := h.ListPreAuthKeys(name)
	if err != nil {
		return err
	}
	for _, p := range keys {
		err = h.DestroyPreAuthKey(&p)
		if err != nil {
			return err
		}
	}

	if result := h.db.Unscoped().Delete(&n); result.Error != nil {
		return result.Error
	}

	return nil
}

// RenameNamespace renames a Namespace. Returns error if the Namespace does
// not exist or if another Namespace exists with the new name.
func (h *Headscale) RenameNamespace(oldName, newName string) error {
	n, err := h.GetNamespace(oldName)
	if err != nil {
		return err
	}
	_, err = h.GetNamespace(newName)
	if err == nil {
		return errorNamespaceExists
	}
	if !errors.Is(err, errorNamespaceNotFound) {
		return err
	}

	n.Name = newName

	if result := h.db.Save(&n); result.Error != nil {
		return result.Error
	}

	err = h.RequestMapUpdates(n.ID)
	if err != nil {
		return err
	}

	return nil
}

// GetNamespace fetches a namespace by name.
func (h *Headscale) GetNamespace(name string) (*Namespace, error) {
	n := Namespace{}
	if result := h.db.First(&n, "name = ?", name); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, errorNamespaceNotFound
	}
	return &n, nil
}

// ListNamespaces gets all the existing namespaces.
func (h *Headscale) ListNamespaces() ([]Namespace, error) {
	namespaces := []Namespace{}
	if err := h.db.Find(&namespaces).Error; err != nil {
		return nil, err
	}
	return namespaces, nil
}

// ListMachinesInNamespace gets all the nodes in a given namespace.
func (h *Headscale) ListMachinesInNamespace(name string) ([]Machine, error) {
	n, err := h.GetNamespace(name)
	if err != nil {
		return nil, err
	}

	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").Where(&Machine{NamespaceID: n.ID}).Find(&machines).Error; err != nil {
		return nil, err
	}
	return machines, nil
}

// ListSharedMachinesInNamespace returns all the machines that are shared to the specified namespace.
func (h *Headscale) ListSharedMachinesInNamespace(name string) ([]Machine, error) {
	namespace, err := h.GetNamespace(name)
	if err != nil {
		return nil, err
	}
	sharedMachines := []SharedMachine{}
	if err := h.db.Preload("Namespace").Where(&SharedMachine{NamespaceID: namespace.ID}).Find(&sharedMachines).Error; err != nil {
		return nil, err
	}

	machines := []Machine{}
	for _, sharedMachine := range sharedMachines {
		machine, err := h.GetMachineByID(
			sharedMachine.MachineID,
		) // otherwise not everything comes filled
		if err != nil {
			return nil, err
		}
		machines = append(machines, *machine)
	}
	return machines, nil
}

// SetMachineNamespace assigns a Machine to a namespace.
func (h *Headscale) SetMachineNamespace(m *Machine, namespaceName string) error {
	n, err := h.GetNamespace(namespaceName)
	if err != nil {
		return err
	}
	m.NamespaceID = n.ID
	h.db.Save(&m)
	return nil
}

// RequestMapUpdates signals the KV worker to update the maps for this namespace.
func (h *Headscale) RequestMapUpdates(namespaceID uint) error {
	namespace := Namespace{}
	if err := h.db.First(&namespace, namespaceID).Error; err != nil {
		return err
	}

	v, err := h.getValue("namespaces_pending_updates")
	if err != nil || v == "" {
		err = h.setValue(
			"namespaces_pending_updates",
			fmt.Sprintf(`["%s"]`, namespace.Name),
		)
		if err != nil {
			return err
		}
		return nil
	}
	names := []string{}
	err = json.Unmarshal([]byte(v), &names)
	if err != nil {
		err = h.setValue(
			"namespaces_pending_updates",
			fmt.Sprintf(`["%s"]`, namespace.Name),
		)
		if err != nil {
			return err
		}
		return nil
	}

	names = append(names, namespace.Name)
	data, err := json.Marshal(names)
	if err != nil {
		log.Error().
			Str("func", "RequestMapUpdates").
			Err(err).
			Msg("Could not marshal namespaces_pending_updates")
		return err
	}
	return h.setValue("namespaces_pending_updates", string(data))
}

func (h *Headscale) checkForNamespacesPendingUpdates() {
	v, err := h.getValue("namespaces_pending_updates")
	if err != nil {
		return
	}
	if v == "" {
		return
	}

	namespaces := []string{}
	err = json.Unmarshal([]byte(v), &namespaces)
	if err != nil {
		return
	}
	for _, namespace := range namespaces {
		log.Trace().
			Str("func", "RequestMapUpdates").
			Str("machine", namespace).
			Msg("Sending updates to nodes in namespacespace")
		h.setLastStateChangeToNow(namespace)
	}
	newV, err := h.getValue("namespaces_pending_updates")
	if err != nil {
		return
	}
	if v == newV { // only clear when no changes, so we notified everybody
		err = h.setValue("namespaces_pending_updates", "")
		if err != nil {
			log.Error().
				Str("func", "checkForNamespacesPendingUpdates").
				Err(err).
				Msg("Could not save to KV")
			return
		}
	}
}

func (n *Namespace) toUser() *tailcfg.User {
	u := tailcfg.User{
		ID:            tailcfg.UserID(n.ID),
		LoginName:     n.Name,
		DisplayName:   n.Name,
		ProfilePicURL: "",
		Domain:        "headscale.net",
		Logins:        []tailcfg.LoginID{},
		Created:       time.Time{},
	}
	return &u
}

func (n *Namespace) toLogin() *tailcfg.Login {
	l := tailcfg.Login{
		ID:            tailcfg.LoginID(n.ID),
		LoginName:     n.Name,
		DisplayName:   n.Name,
		ProfilePicURL: "",
		Domain:        "headscale.net",
	}
	return &l
}

func getMapResponseUserProfiles(m Machine, peers Machines) []tailcfg.UserProfile {
	namespaceMap := make(map[string]Namespace)
	namespaceMap[m.Namespace.Name] = m.Namespace
	for _, p := range peers {
		namespaceMap[p.Namespace.Name] = p.Namespace // not worth checking if already is there
	}

	profiles := []tailcfg.UserProfile{}
	for _, namespace := range namespaceMap {
		profiles = append(profiles,
			tailcfg.UserProfile{
				ID:          tailcfg.UserID(namespace.ID),
				LoginName:   namespace.Name,
				DisplayName: namespace.Name,
			})
	}
	return profiles
}

func (n *Namespace) toProto() *v1.Namespace {
	return &v1.Namespace{
		Id:        strconv.FormatUint(uint64(n.ID), 10),
		Name:      n.Name,
		CreatedAt: timestamppb.New(n.CreatedAt),
	}
}
