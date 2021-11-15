package headscale

import (
	"time"

	"gopkg.in/check.v1"
)

func (s *Suite) TestRegisterMachine(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	now := time.Now().UTC()

	machine := Machine{
		ID:              0,
		MachineKey:      "8ce002a935f8c394e55e78fbbb410576575ff8ec5cfa2e627e4b807f1be15b0e",
		NodeKey:         "bar",
		DiscoKey:        "faa",
		Name:            "testmachine",
		NamespaceID:     namespace.ID,
		IPAddress:       "10.0.0.1",
		Expiry:          &now,
		RequestedExpiry: &now,
	}
	app.db.Save(&machine)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)

	machineAfterRegistering, err := app.RegisterMachine(
		"8ce002a935f8c394e55e78fbbb410576575ff8ec5cfa2e627e4b807f1be15b0e",
		namespace.Name,
	)
	c.Assert(err, check.IsNil)
	c.Assert(machineAfterRegistering.Registered, check.Equals, true)

	_, err = machineAfterRegistering.GetHostInfo()
	c.Assert(err, check.IsNil)
}
