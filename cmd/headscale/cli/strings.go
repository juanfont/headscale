package cli

// Shared CLI vocabulary used across multiple command definitions in this
// package. Centralising the strings prevents goconst drift and ensures a
// typo in a subcommand name fails to compile rather than silently
// breaking the binding.
const (
	// Subcommand verbs (cobra Use field).
	cmdList   = "list"
	cmdShow   = "show"
	cmdNew    = "new"
	cmdDelete = "delete"
	cmdExpire = "expire"

	// Subcommand aliases.
	aliasDel = "del"
	aliasExp = "exp"

	// Output table column headers and printOutput map keys.
	colResult     = "Result"
	colCreated    = "Created"
	colExpiration = "Expiration"
)
