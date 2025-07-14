package cli

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
)

// Flag registration helpers - standardize how flags are added to commands

// AddIdentifierFlag adds a uint64 identifier flag with consistent naming
func AddIdentifierFlag(cmd *cobra.Command, name string, help string) {
	cmd.Flags().Uint64P(name, "i", 0, help)
}

// AddRequiredIdentifierFlag adds a required uint64 identifier flag
func AddRequiredIdentifierFlag(cmd *cobra.Command, name string, help string) {
	AddIdentifierFlag(cmd, name, help)
	err := cmd.MarkFlagRequired(name)
	if err != nil {
		log.Fatal(err.Error())
	}
}

// AddUserFlag adds a user flag (string for username or email)
func AddUserFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("user", "u", "", "User")
}

// AddRequiredUserFlag adds a required user flag
func AddRequiredUserFlag(cmd *cobra.Command) {
	AddUserFlag(cmd)
	err := cmd.MarkFlagRequired("user")
	if err != nil {
		log.Fatal(err.Error())
	}
}

// AddOutputFlag adds the standard output format flag
func AddOutputFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("output", "o", "", "Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'")
}

// AddForceFlag adds the force flag
func AddForceFlag(cmd *cobra.Command) {
	cmd.Flags().Bool("force", false, "Disable prompts and forces the execution")
}

// AddExpirationFlag adds an expiration duration flag
func AddExpirationFlag(cmd *cobra.Command, defaultValue string) {
	cmd.Flags().StringP("expiration", "e", defaultValue, "Human-readable duration (e.g. 30m, 24h)")
}

// AddDeprecatedNamespaceFlag adds the deprecated namespace flag with appropriate warnings
func AddDeprecatedNamespaceFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("namespace", "n", "", "User")
	namespaceFlag := cmd.Flags().Lookup("namespace")
	namespaceFlag.Deprecated = deprecateNamespaceMessage
	namespaceFlag.Hidden = true
}

// AddTagsFlag adds a tags display flag
func AddTagsFlag(cmd *cobra.Command) {
	cmd.Flags().BoolP("tags", "t", false, "Show tags")
}

// AddKeyFlag adds a key flag for node registration
func AddKeyFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("key", "k", "", "Key")
}

// AddRequiredKeyFlag adds a required key flag
func AddRequiredKeyFlag(cmd *cobra.Command) {
	AddKeyFlag(cmd)
	err := cmd.MarkFlagRequired("key")
	if err != nil {
		log.Fatal(err.Error())
	}
}

// AddNameFlag adds a name flag
func AddNameFlag(cmd *cobra.Command, help string) {
	cmd.Flags().String("name", "", help)
}

// AddRequiredNameFlag adds a required name flag
func AddRequiredNameFlag(cmd *cobra.Command, help string) {
	AddNameFlag(cmd, help)
	err := cmd.MarkFlagRequired("name")
	if err != nil {
		log.Fatal(err.Error())
	}
}

// AddPrefixFlag adds an API key prefix flag
func AddPrefixFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("prefix", "p", "", "ApiKey prefix")
}

// AddRequiredPrefixFlag adds a required API key prefix flag
func AddRequiredPrefixFlag(cmd *cobra.Command) {
	AddPrefixFlag(cmd)
	err := cmd.MarkFlagRequired("prefix")
	if err != nil {
		log.Fatal(err.Error())
	}
}

// AddFileFlag adds a file path flag
func AddFileFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
}

// AddRequiredFileFlag adds a required file path flag
func AddRequiredFileFlag(cmd *cobra.Command) {
	AddFileFlag(cmd)
	err := cmd.MarkFlagRequired("file")
	if err != nil {
		log.Fatal(err.Error())
	}
}

// AddRoutesFlag adds a routes flag for node route management
func AddRoutesFlag(cmd *cobra.Command) {
	cmd.Flags().StringSliceP("routes", "r", []string{}, `List of routes that will be approved (comma-separated, e.g. "10.0.0.0/8,192.168.0.0/24" or empty string to remove all approved routes)`)
}

// AddTagsSliceFlag adds a tags slice flag for node tagging
func AddTagsSliceFlag(cmd *cobra.Command) {
	cmd.Flags().StringSliceP("tags", "t", []string{}, "List of tags to add to the node")
}

// Flag getter helpers with consistent error handling

// GetIdentifier gets a uint64 identifier flag value with error handling
func GetIdentifier(cmd *cobra.Command, flagName string) (uint64, error) {
	identifier, err := cmd.Flags().GetUint64(flagName)
	if err != nil {
		return 0, fmt.Errorf("error getting %s flag: %w", flagName, err)
	}
	return identifier, nil
}

// GetUser gets a user flag value
func GetUser(cmd *cobra.Command) (string, error) {
	user, err := cmd.Flags().GetString("user")
	if err != nil {
		return "", fmt.Errorf("error getting user flag: %w", err)
	}
	return user, nil
}

// GetOutputFormat gets the output format flag value
func GetOutputFormat(cmd *cobra.Command) string {
	output, _ := cmd.Flags().GetString("output")
	return output
}

// GetForce gets the force flag value
func GetForce(cmd *cobra.Command) bool {
	force, _ := cmd.Flags().GetBool("force")
	return force
}

// GetExpiration gets and parses the expiration flag value
func GetExpiration(cmd *cobra.Command) (time.Duration, error) {
	expirationStr, err := cmd.Flags().GetString("expiration")
	if err != nil {
		return 0, fmt.Errorf("error getting expiration flag: %w", err)
	}
	
	if expirationStr == "" {
		return 0, nil // No expiration set
	}
	
	duration, err := time.ParseDuration(expirationStr)
	if err != nil {
		return 0, fmt.Errorf("invalid expiration duration '%s': %w", expirationStr, err)
	}
	
	return duration, nil
}

// GetName gets a name flag value
func GetName(cmd *cobra.Command) (string, error) {
	name, err := cmd.Flags().GetString("name")
	if err != nil {
		return "", fmt.Errorf("error getting name flag: %w", err)
	}
	return name, nil
}

// GetKey gets a key flag value
func GetKey(cmd *cobra.Command) (string, error) {
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return "", fmt.Errorf("error getting key flag: %w", err)
	}
	return key, nil
}

// GetPrefix gets a prefix flag value
func GetPrefix(cmd *cobra.Command) (string, error) {
	prefix, err := cmd.Flags().GetString("prefix")
	if err != nil {
		return "", fmt.Errorf("error getting prefix flag: %w", err)
	}
	return prefix, nil
}

// GetFile gets a file flag value
func GetFile(cmd *cobra.Command) (string, error) {
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return "", fmt.Errorf("error getting file flag: %w", err)
	}
	return file, nil
}

// GetRoutes gets a routes flag value
func GetRoutes(cmd *cobra.Command) ([]string, error) {
	routes, err := cmd.Flags().GetStringSlice("routes")
	if err != nil {
		return nil, fmt.Errorf("error getting routes flag: %w", err)
	}
	return routes, nil
}

// GetTagsSlice gets a tags slice flag value
func GetTagsSlice(cmd *cobra.Command) ([]string, error) {
	tags, err := cmd.Flags().GetStringSlice("tags")
	if err != nil {
		return nil, fmt.Errorf("error getting tags flag: %w", err)
	}
	return tags, nil
}

// GetTags gets a tags boolean flag value
func GetTags(cmd *cobra.Command) bool {
	tags, _ := cmd.Flags().GetBool("tags")
	return tags
}

// Flag validation helpers

// ValidateRequiredFlags validates that required flags are set
func ValidateRequiredFlags(cmd *cobra.Command, flags ...string) error {
	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			return fmt.Errorf("flag %s not found", flagName)
		}
		
		if !flag.Changed {
			return fmt.Errorf("required flag %s not set", flagName)
		}
	}
	return nil
}

// ValidateExclusiveFlags validates that only one of the given flags is set
func ValidateExclusiveFlags(cmd *cobra.Command, flags ...string) error {
	setFlags := []string{}
	
	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			return fmt.Errorf("flag %s not found", flagName)
		}
		
		if flag.Changed {
			setFlags = append(setFlags, flagName)
		}
	}
	
	if len(setFlags) > 1 {
		return fmt.Errorf("only one of the following flags can be set: %v, but found: %v", flags, setFlags)
	}
	
	return nil
}

// ValidateIdentifierFlag validates that an identifier flag has a valid value
func ValidateIdentifierFlag(cmd *cobra.Command, flagName string) error {
	identifier, err := GetIdentifier(cmd, flagName)
	if err != nil {
		return err
	}
	
	if identifier == 0 {
		return fmt.Errorf("%s must be greater than 0", flagName)
	}
	
	return nil
}

// ValidateNonEmptyStringFlag validates that a string flag is not empty
func ValidateNonEmptyStringFlag(cmd *cobra.Command, flagName string) error {
	value, err := cmd.Flags().GetString(flagName)
	if err != nil {
		return fmt.Errorf("error getting %s flag: %w", flagName, err)
	}
	
	if value == "" {
		return fmt.Errorf("%s cannot be empty", flagName)
	}
	
	return nil
}

// Deprecated flag handling utilities

// HandleDeprecatedNamespaceFlag handles the deprecated namespace flag by copying its value to user flag
func HandleDeprecatedNamespaceFlag(cmd *cobra.Command) {
	namespaceFlag := cmd.Flags().Lookup("namespace")
	userFlag := cmd.Flags().Lookup("user")
	
	if namespaceFlag != nil && userFlag != nil && namespaceFlag.Changed && !userFlag.Changed {
		// Copy namespace value to user flag
		userFlag.Value.Set(namespaceFlag.Value.String())
		userFlag.Changed = true
	}
}

// GetUserWithDeprecatedNamespace gets user value, checking both user and deprecated namespace flags
func GetUserWithDeprecatedNamespace(cmd *cobra.Command) (string, error) {
	user, err := cmd.Flags().GetString("user")
	if err != nil {
		return "", fmt.Errorf("error getting user flag: %w", err)
	}
	
	// If user is empty, try deprecated namespace flag
	if user == "" {
		namespace, err := cmd.Flags().GetString("namespace")
		if err == nil && namespace != "" {
			return namespace, nil
		}
	}
	
	return user, nil
}