package headscale

import "gorm.io/gorm"

const errorSameNamespace = Error("Destination namespace same as origin")
const errorMachineAlreadyShared = Error("Node already shared to this namespace")
const errorMachineNotShared = Error("Machine not shared to this namespace")

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

	sharedMachines := []SharedMachine{}
	if err := h.db.Where("machine_id = ? AND namespace_id = ?", m.ID, ns.ID).Find(&sharedMachines).Error; err != nil {
		return err
	}
	if len(sharedMachines) > 0 {
		return errorMachineAlreadyShared
	}

	sharedMachine := SharedMachine{
		MachineID:   m.ID,
		Machine:     *m,
		NamespaceID: ns.ID,
		Namespace:   *ns,
	}
	h.db.Save(&sharedMachine)

	return nil
}

// RemoveSharedMachineFromNamespace removes a shared machine from a namespace
func (h *Headscale) RemoveSharedMachineFromNamespace(m *Machine, ns *Namespace) error {
	if m.NamespaceID == ns.ID {
		return errorSameNamespace
	}

	sharedMachine := SharedMachine{}
	result := h.db.Where("machine_id = ? AND namespace_id = ?", m.ID, ns.ID).Unscoped().Delete(&sharedMachine)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return errorMachineNotShared
	}

	err := h.RequestMapUpdates(ns.ID)
	if err != nil {
		return err
	}

	return nil
}

// RemoveSharedMachineFromAllNamespaces removes a machine as a shared node from all namespaces
func (h *Headscale) RemoveSharedMachineFromAllNamespaces(m *Machine) error {
	sharedMachine := SharedMachine{}
	if result := h.db.Where("machine_id = ?", m.ID).Unscoped().Delete(&sharedMachine); result.Error != nil {
		return result.Error
	}

	return nil
}
