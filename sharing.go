package headscale

import "gorm.io/gorm"

const errorSameNamespace = Error("Destination namespace same as origin")
const errorMachineAlreadyShared = Error("Node already shared to this namespace")

// SharedMachine is a join table to support sharing nodes between namespaces
type SharedMachine struct {
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

	sn := SharedMachine{}
	if err := h.db.Where("machine_id = ? AND namespace_id", m.ID, ns.ID).First(&sharedMachine).Error; err == nil {
		return errorMachineAlreadyShared
	}

	sharedMachine = SharedMachine{
		MachineID:   m.ID,
		Machine:     *m,
		NamespaceID: ns.ID,
		Namespace:   *ns,
	}
	h.db.Save(&sharedMachine)

	return nil
}
