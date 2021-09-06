package headscale

import "gorm.io/gorm"

const errorSameNamespace = Error("Destination namespace same as origin")
const errorNodeAlreadyShared = Error("Node already shared to this namespace")

// SharedNode is a join table to support sharing nodes between namespaces
type SharedNode struct {
	gorm.Model
	MachineID   uint64
	Machine     Machine
	NamespaceID uint
	Namespace   Namespace
}

// AddSharedMachineToNamespace adds a machine as a shared node to a namespace
func (h *Headscale) AddSharedMachineToNamespace(m *Machine, ns *Namespace) error {
	if m.NamespaceID == ns.ID {
		return errorSameNamespace
	}

	sn := SharedNode{}
	if err := h.db.Where("machine_id = ? AND namespace_id", m.ID, ns.ID).First(&sn).Error; err == nil {
		return errorNodeAlreadyShared
	}

	sn = SharedNode{
		MachineID:   m.ID,
		Machine:     *m,
		NamespaceID: ns.ID,
		Namespace:   *ns,
	}
	h.db.Save(&sn)

	return nil
}
