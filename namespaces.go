package headscale

import (
	"errors"
	"log"
	"time"

	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

const errorNamespaceExists = Error("Namespace already exists")
const errorNamespaceNotFound = Error("Namespace not found")
const errorNamespaceNotEmpty = Error("Namespace not empty")

// Namespace is the way Headscale implements the concept of users in Tailscale
//
// At the end of the day, users in Tailscale are some kind of 'bubbles' or namespaces
// that contain our machines.
type Namespace struct {
	gorm.Model
	Name string `gorm:"unique"`
}

// CreateNamespace creates a new Namespace. Returns error if could not be created
// or another namespace already exists
func (h *Headscale) CreateNamespace(name string) (*Namespace, error) {
	n := Namespace{}
	if err := h.db.Where("name = ?", name).First(&n).Error; err == nil {
		return nil, errorNamespaceExists
	}
	n.Name = name
	if err := h.db.Create(&n).Error; err != nil {
		log.Printf("Could not create row: %s", err)
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
	if len(*m) > 0 {
		return errorNamespaceNotEmpty
	}

	if result := h.db.Unscoped().Delete(&n); result.Error != nil {
		return err
	}

	return nil
}

// GetNamespace fetches a namespace by name
func (h *Headscale) GetNamespace(name string) (*Namespace, error) {
	n := Namespace{}
	if result := h.db.First(&n, "name = ?", name); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, errorNamespaceNotFound
	}
	return &n, nil
}

// ListNamespaces gets all the existing namespaces
func (h *Headscale) ListNamespaces() (*[]Namespace, error) {
	namespaces := []Namespace{}
	if err := h.db.Find(&namespaces).Error; err != nil {
		return nil, err
	}
	return &namespaces, nil
}

// ListMachinesInNamespace gets all the nodes in a given namespace
func (h *Headscale) ListMachinesInNamespace(name string) (*[]Machine, error) {
	n, err := h.GetNamespace(name)
	if err != nil {
		return nil, err
	}

	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Where(&Machine{NamespaceID: n.ID}).Find(&machines).Error; err != nil {
		return nil, err
	}
	return &machines, nil
}

// SetMachineNamespace assigns a Machine to a namespace
func (h *Headscale) SetMachineNamespace(m *Machine, namespaceName string) error {
	n, err := h.GetNamespace(namespaceName)
	if err != nil {
		return err
	}
	m.NamespaceID = n.ID
	h.db.Save(&m)
	return nil
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
