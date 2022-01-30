package headscale

import "gorm.io/gorm"

const (
	errSameNamespace        = Error("Destination namespace same as origin")
	errMachineAlreadyShared = Error("Node already shared to this namespace")
	errMachineNotShared     = Error("Machine not shared to this namespace")
)

// SharedMachine is a join table to support sharing nodes between namespaces.
type SharedMachine struct {
	gorm.Model
	MachineID   uint64
	Machine     Machine
	NamespaceID uint
	Namespace   Namespace
}

// AddSharedMachineToNamespace adds a machine as a shared node to a namespace.
func (h *Headscale) AddSharedMachineToNamespace(
	machine *Machine,
	namespace *Namespace,
) error {
	if machine.NamespaceID == namespace.ID {
		return errSameNamespace
	}

	sharedMachines := []SharedMachine{}
	if err := h.db.Where("machine_id = ? AND namespace_id = ?", machine.ID, namespace.ID).Find(&sharedMachines).Error; err != nil {
		return err
	}
	if len(sharedMachines) > 0 {
		return errMachineAlreadyShared
	}

	sharedMachine := SharedMachine{
		MachineID:   machine.ID,
		Machine:     *machine,
		NamespaceID: namespace.ID,
		Namespace:   *namespace,
	}
	h.db.Save(&sharedMachine)

	return nil
}

// RemoveSharedMachineFromNamespace removes a shared machine from a namespace.
func (h *Headscale) RemoveSharedMachineFromNamespace(
	machine *Machine,
	namespace *Namespace,
) error {
	if machine.NamespaceID == namespace.ID {
		// Can't unshare from primary namespace
		return errMachineNotShared
	}

	sharedMachine := SharedMachine{}
	result := h.db.Where("machine_id = ? AND namespace_id = ?", machine.ID, namespace.ID).
		Unscoped().
		Delete(&sharedMachine)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return errMachineNotShared
	}

	err := h.RequestMapUpdates(namespace.ID)
	if err != nil {
		return err
	}

	return nil
}

// RemoveSharedMachineFromAllNamespaces removes a machine as a shared node from all namespaces.
func (h *Headscale) RemoveSharedMachineFromAllNamespaces(machine *Machine) error {
	sharedMachine := SharedMachine{}
	if result := h.db.Where("machine_id = ?", machine.ID).Unscoped().Delete(&sharedMachine); result.Error != nil {
		return result.Error
	}

	return nil
}
