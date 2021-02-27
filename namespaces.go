package headscale

import (
	"fmt"
	"log"
	"time"

	"github.com/jinzhu/gorm"
	"tailscale.com/tailcfg"
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
// or another namespace already exists
func (h *Headscale) CreateNamespace(name string) (*Namespace, error) {
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return nil, err
	}
	defer db.Close()

	n := Namespace{}
	if err := db.Where("name = ?", name).First(&n).Error; err == nil {
		return nil, fmt.Errorf("Namespace already exists")
	}
	n.Name = name
	if err := db.Create(&n).Error; err != nil {
		log.Printf("Could not create row: %s", err)
		return nil, err
	}
	return &n, nil
}

// GetNamespace fetches a namespace by name
func (h *Headscale) GetNamespace(name string) (*Namespace, error) {
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return nil, err
	}
	defer db.Close()

	n := Namespace{}
	if db.First(&n, "name = ?", name).RecordNotFound() {
		return nil, fmt.Errorf("Namespace not found")
	}
	return &n, nil
}

// ListNamespaces gets all the existing namespaces
func (h *Headscale) ListNamespaces() (*[]Namespace, error) {
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return nil, err
	}
	defer db.Close()
	namespaces := []Namespace{}
	if err := db.Find(&namespaces).Error; err != nil {
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
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return nil, err
	}
	defer db.Close()

	machines := []Machine{}
	if err := db.Where(&Machine{NamespaceID: n.ID}).Find(&machines).Error; err != nil {
		return nil, err
	}
	return &machines, nil
}

func (h *Headscale) SetMachineNamespace(m *Machine, namespaceName string) error {
	n, err := h.GetNamespace(namespaceName)
	if err != nil {
		return err
	}
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return err
	}
	defer db.Close()
	m.NamespaceID = n.ID
	db.Save(&m)
	return nil
}

func (n *Namespace) toUser() *tailcfg.User {
	u := tailcfg.User{
		ID:            tailcfg.UserID(n.ID),
		LoginName:     "",
		DisplayName:   n.Name,
		ProfilePicURL: "",
		Domain:        "",
		Logins:        []tailcfg.LoginID{},
		Roles:         []tailcfg.RoleID{},
		Created:       time.Time{},
	}
	return &u
}
