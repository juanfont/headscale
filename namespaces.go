package headscale

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

const (
	ErrNamespaceExists          = Error("Namespace already exists")
	ErrNamespaceNotFound        = Error("Namespace not found")
	ErrNamespaceNotEmptyOfNodes = Error("Namespace not empty: node(s) found")
	ErrInvalidNamespaceName     = Error("Invalid namespace name")
)

const (
	// value related to RFC 1123 and 952.
	labelHostnameLength = 63
)

var invalidCharsInNamespaceRegex = regexp.MustCompile("[^a-z0-9-.]+")

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
	err := CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	namespace := Namespace{}
	if err := h.db.Where("name = ?", name).First(&namespace).Error; err == nil {
		return nil, ErrNamespaceExists
	}
	namespace.Name = name
	if err := h.db.Create(&namespace).Error; err != nil {
		log.Error().
			Str("func", "CreateNamespace").
			Err(err).
			Msg("Could not create row")

		return nil, err
	}

	return &namespace, nil
}

// DestroyNamespace destroys a Namespace. Returns error if the Namespace does
// not exist or if there are machines associated with it.
func (h *Headscale) DestroyNamespace(name string) error {
	namespace, err := h.GetNamespace(name)
	if err != nil {
		return ErrNamespaceNotFound
	}

	machines, err := h.ListMachinesInNamespace(name)
	if err != nil {
		return err
	}
	if len(machines) > 0 {
		return ErrNamespaceNotEmptyOfNodes
	}

	keys, err := h.ListPreAuthKeys(name)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err = h.DestroyPreAuthKey(key)
		if err != nil {
			return err
		}
	}

	if result := h.db.Unscoped().Delete(&namespace); result.Error != nil {
		return result.Error
	}

	return nil
}

// RenameNamespace renames a Namespace. Returns error if the Namespace does
// not exist or if another Namespace exists with the new name.
func (h *Headscale) RenameNamespace(oldName, newName string) error {
	var err error
	oldNamespace, err := h.GetNamespace(oldName)
	if err != nil {
		return err
	}
	err = CheckForFQDNRules(newName)
	if err != nil {
		return err
	}
	_, err = h.GetNamespace(newName)
	if err == nil {
		return ErrNamespaceExists
	}
	if !errors.Is(err, ErrNamespaceNotFound) {
		return err
	}

	oldNamespace.Name = newName

	if result := h.db.Save(&oldNamespace); result.Error != nil {
		return result.Error
	}

	return nil
}

// GetNamespace fetches a namespace by name.
func (h *Headscale) GetNamespace(name string) (*Namespace, error) {
	namespace := Namespace{}
	if result := h.db.First(&namespace, "name = ?", name); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrNamespaceNotFound
	}

	return &namespace, nil
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
	err := CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	namespace, err := h.GetNamespace(name)
	if err != nil {
		return nil, err
	}

	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").Where(&Machine{NamespaceID: namespace.ID}).Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

// SetMachineNamespace assigns a Machine to a namespace.
func (h *Headscale) SetMachineNamespace(machine *Machine, namespaceName string) error {
	err := CheckForFQDNRules(namespaceName)
	if err != nil {
		return err
	}
	namespace, err := h.GetNamespace(namespaceName)
	if err != nil {
		return err
	}
	machine.Namespace = *namespace
	if result := h.db.Save(&machine); result.Error != nil {
		return result.Error
	}

	return nil
}

func (n *Namespace) toUser() *tailcfg.User {
	user := tailcfg.User{
		ID:            tailcfg.UserID(n.ID),
		LoginName:     n.Name,
		DisplayName:   n.Name,
		ProfilePicURL: "",
		Domain:        "headscale.net",
		Logins:        []tailcfg.LoginID{},
		Created:       time.Time{},
	}

	return &user
}

func (n *Namespace) toLogin() *tailcfg.Login {
	login := tailcfg.Login{
		ID:            tailcfg.LoginID(n.ID),
		LoginName:     n.Name,
		DisplayName:   n.Name,
		ProfilePicURL: "",
		Domain:        "headscale.net",
	}

	return &login
}

func (h *Headscale) getMapResponseUserProfiles(
	machine Machine,
	peers Machines,
) []tailcfg.UserProfile {
	namespaceMap := make(map[string]Namespace)
	namespaceMap[machine.Namespace.Name] = machine.Namespace
	for _, peer := range peers {
		namespaceMap[peer.Namespace.Name] = peer.Namespace // not worth checking if already is there
	}

	profiles := []tailcfg.UserProfile{}
	for _, namespace := range namespaceMap {
		displayName := namespace.Name

		if h.cfg.BaseDomain != "" {
			displayName = fmt.Sprintf("%s@%s", namespace.Name, h.cfg.BaseDomain)
		}

		profiles = append(profiles,
			tailcfg.UserProfile{
				ID:          tailcfg.UserID(namespace.ID),
				LoginName:   namespace.Name,
				DisplayName: displayName,
			})
	}

	return profiles
}

func (n *Namespace) toProto() *v1.Namespace {
	return &v1.Namespace{
		Id:        strconv.FormatUint(uint64(n.ID), Base10),
		Name:      n.Name,
		CreatedAt: timestamppb.New(n.CreatedAt),
	}
}

// NormalizeToFQDNRules will replace forbidden chars in namespace
// it can also return an error if the namespace doesn't respect RFC 952 and 1123.
func NormalizeToFQDNRules(name string, stripEmailDomain bool) (string, error) {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "'", "")
	atIdx := strings.Index(name, "@")
	if stripEmailDomain && atIdx > 0 {
		name = name[:atIdx]
	} else {
		name = strings.ReplaceAll(name, "@", ".")
	}
	name = invalidCharsInNamespaceRegex.ReplaceAllString(name, "-")

	for _, elt := range strings.Split(name, ".") {
		if len(elt) > labelHostnameLength {
			return "", fmt.Errorf(
				"label %v is more than 63 chars: %w",
				elt,
				ErrInvalidNamespaceName,
			)
		}
	}

	return name, nil
}

func CheckForFQDNRules(name string) error {
	if len(name) > labelHostnameLength {
		return fmt.Errorf(
			"DNS segment must not be over 63 chars. %v doesn't comply with this rule: %w",
			name,
			ErrInvalidNamespaceName,
		)
	}
	if strings.ToLower(name) != name {
		return fmt.Errorf(
			"DNS segment should be lowercase. %v doesn't comply with this rule: %w",
			name,
			ErrInvalidNamespaceName,
		)
	}
	if invalidCharsInNamespaceRegex.MatchString(name) {
		return fmt.Errorf(
			"DNS segment should only be composed of lowercase ASCII letters numbers, hyphen and dots. %v doesn't comply with theses rules: %w",
			name,
			ErrInvalidNamespaceName,
		)
	}

	return nil
}
