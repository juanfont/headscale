package cli

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Input validation utilities

// ValidateEmail validates that a string is a valid email address
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address '%s': %w", email, err)
	}
	
	return nil
}

// ValidateURL validates that a string is a valid URL
func ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL '%s': %w", urlStr, err)
	}
	
	if parsedURL.Scheme == "" {
		return fmt.Errorf("URL '%s' must include a scheme (http:// or https://)", urlStr)
	}
	
	if parsedURL.Host == "" {
		return fmt.Errorf("URL '%s' must include a host", urlStr)
	}
	
	return nil
}

// ValidateDuration validates and parses a duration string
func ValidateDuration(duration string) (time.Duration, error) {
	if duration == "" {
		return 0, fmt.Errorf("duration cannot be empty")
	}
	
	parsed, err := time.ParseDuration(duration)
	if err != nil {
		return 0, fmt.Errorf("invalid duration '%s': %w (use format like '1h', '30m', '24h')", duration, err)
	}
	
	if parsed < 0 {
		return 0, fmt.Errorf("duration '%s' cannot be negative", duration)
	}
	
	return parsed, nil
}

// ValidateUserName validates that a username follows valid patterns
func ValidateUserName(name string) error {
	if name == "" {
		return fmt.Errorf("username cannot be empty")
	}
	
	// Username length validation
	if len(name) < 1 {
		return fmt.Errorf("username must be at least 1 character long")
	}
	
	if len(name) > 64 {
		return fmt.Errorf("username cannot be longer than 64 characters")
	}
	
	// Allow alphanumeric, dots, hyphens, underscores, and @ symbol for email-style usernames
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`)
	if !validPattern.MatchString(name) {
		return fmt.Errorf("username '%s' contains invalid characters (only letters, numbers, dots, hyphens, underscores, and @ are allowed)", name)
	}
	
	// Cannot start or end with dots or hyphens
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("username '%s' cannot start or end with a dot", name)
	}
	
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return fmt.Errorf("username '%s' cannot start or end with a hyphen", name)
	}
	
	return nil
}

// ValidateNodeName validates that a node name follows valid patterns
func ValidateNodeName(name string) error {
	if name == "" {
		return fmt.Errorf("node name cannot be empty")
	}
	
	// Node name length validation
	if len(name) < 1 {
		return fmt.Errorf("node name must be at least 1 character long")
	}
	
	if len(name) > 63 {
		return fmt.Errorf("node name cannot be longer than 63 characters (DNS hostname limit)")
	}
	
	// Valid DNS hostname pattern
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)
	if !validPattern.MatchString(name) {
		return fmt.Errorf("node name '%s' must be a valid DNS hostname (alphanumeric and hyphens, cannot start or end with hyphen)", name)
	}
	
	return nil
}

// ValidateIPAddress validates that a string is a valid IP address
func ValidateIPAddress(ipStr string) error {
	if ipStr == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address '%s'", ipStr)
	}
	
	return nil
}

// ValidateCIDR validates that a string is a valid CIDR network
func ValidateCIDR(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("CIDR cannot be empty")
	}
	
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR '%s': %w", cidr, err)
	}
	
	return nil
}

// Business logic validation

// ValidateTagsFormat validates that tags follow the expected format
func ValidateTagsFormat(tags []string) error {
	if len(tags) == 0 {
		return nil // Empty tags are valid
	}
	
	for _, tag := range tags {
		if err := ValidateTagFormat(tag); err != nil {
			return err
		}
	}
	
	return nil
}

// ValidateTagFormat validates a single tag format
func ValidateTagFormat(tag string) error {
	if tag == "" {
		return fmt.Errorf("tag cannot be empty")
	}
	
	// Tags should follow the format "tag:value" or just "tag"
	if strings.Contains(tag, " ") {
		return fmt.Errorf("tag '%s' cannot contain spaces", tag)
	}
	
	// Check for valid tag characters
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9:._-]+$`)
	if !validPattern.MatchString(tag) {
		return fmt.Errorf("tag '%s' contains invalid characters (only letters, numbers, colons, dots, underscores, and hyphens are allowed)", tag)
	}
	
	// If it contains a colon, validate tag:value format
	if strings.Contains(tag, ":") {
		parts := strings.SplitN(tag, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("tag '%s' with colon must be in format 'tag:value'", tag)
		}
	}
	
	return nil
}

// ValidateRoutesFormat validates that routes follow the expected CIDR format
func ValidateRoutesFormat(routes []string) error {
	if len(routes) == 0 {
		return nil // Empty routes are valid
	}
	
	for _, route := range routes {
		if err := ValidateCIDR(route); err != nil {
			return fmt.Errorf("invalid route: %w", err)
		}
	}
	
	return nil
}

// ValidateAPIKeyPrefix validates that an API key prefix follows valid patterns
func ValidateAPIKeyPrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("API key prefix cannot be empty")
	}
	
	// Prefix length validation
	if len(prefix) < 4 {
		return fmt.Errorf("API key prefix must be at least 4 characters long")
	}
	
	if len(prefix) > 16 {
		return fmt.Errorf("API key prefix cannot be longer than 16 characters")
	}
	
	// Only alphanumeric characters allowed
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !validPattern.MatchString(prefix) {
		return fmt.Errorf("API key prefix '%s' can only contain letters and numbers", prefix)
	}
	
	return nil
}

// ValidatePreAuthKeyOptions validates preauth key creation options
func ValidatePreAuthKeyOptions(reusable bool, ephemeral bool, expiration time.Duration) error {
	// Ephemeral keys cannot be reusable
	if ephemeral && reusable {
		return fmt.Errorf("ephemeral keys cannot be reusable")
	}
	
	// Validate expiration for ephemeral keys
	if ephemeral && expiration == 0 {
		return fmt.Errorf("ephemeral keys must have an expiration time")
	}
	
	// Validate reasonable expiration limits
	if expiration > 0 {
		maxExpiration := 365 * 24 * time.Hour // 1 year
		if expiration > maxExpiration {
			return fmt.Errorf("expiration cannot be longer than 1 year")
		}
		
		minExpiration := 1 * time.Minute
		if expiration < minExpiration {
			return fmt.Errorf("expiration cannot be shorter than 1 minute")
		}
	}
	
	return nil
}

// Pre-flight validation - checks if resources exist

// ValidateUserExists validates that a user exists in the system
func ValidateUserExists(client *ClientWrapper, userID uint64, output string) error {
	if userID == 0 {
		return fmt.Errorf("user ID cannot be zero")
	}
	
	response, err := client.ListUsers(nil, &v1.ListUsersRequest{})
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}
	
	for _, user := range response.GetUsers() {
		if user.GetId() == userID {
			return nil // User exists
		}
	}
	
	return fmt.Errorf("user with ID %d does not exist", userID)
}

// ValidateUserExistsByName validates that a user exists in the system by name
func ValidateUserExistsByName(client *ClientWrapper, userName string, output string) (*v1.User, error) {
	if userName == "" {
		return nil, fmt.Errorf("user name cannot be empty")
	}
	
	response, err := client.ListUsers(nil, &v1.ListUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	
	for _, user := range response.GetUsers() {
		if user.GetName() == userName {
			return user, nil // User exists
		}
	}
	
	return nil, fmt.Errorf("user with name '%s' does not exist", userName)
}

// ValidateNodeExists validates that a node exists in the system
func ValidateNodeExists(client *ClientWrapper, nodeID uint64, output string) error {
	if nodeID == 0 {
		return fmt.Errorf("node ID cannot be zero")
	}
	
	// Get all nodes and check if the ID exists
	response, err := client.ListNodes(nil, &v1.ListNodesRequest{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}
	
	for _, node := range response.GetNodes() {
		if node.GetId() == nodeID {
			return nil // Node exists
		}
	}
	
	return fmt.Errorf("node with ID %d does not exist", nodeID)
}

// ValidateNodeExistsByIdentifier validates that a node exists in the system by identifier
func ValidateNodeExistsByIdentifier(client *ClientWrapper, identifier string, output string) (*v1.Node, error) {
	if identifier == "" {
		return nil, fmt.Errorf("node identifier cannot be empty")
	}
	
	// Try to resolve the node by identifier
	node, err := ResolveNodeByIdentifier(client, nil, identifier)
	if err != nil {
		return nil, fmt.Errorf("node '%s' does not exist: %w", identifier, err)
	}
	
	return node, nil
}

// ValidateAPIKeyExists validates that an API key exists in the system
func ValidateAPIKeyExists(client *ClientWrapper, prefix string, output string) error {
	if prefix == "" {
		return fmt.Errorf("API key prefix cannot be empty")
	}
	
	// Get all API keys and check if the prefix exists
	response, err := client.ListApiKeys(nil, &v1.ListApiKeysRequest{})
	if err != nil {
		return fmt.Errorf("failed to list API keys: %w", err)
	}
	
	for _, apiKey := range response.GetApiKeys() {
		if apiKey.GetPrefix() == prefix {
			return nil // API key exists
		}
	}
	
	return fmt.Errorf("API key with prefix '%s' does not exist", prefix)
}

// ValidatePreAuthKeyExists validates that a preauth key exists in the system
func ValidatePreAuthKeyExists(client *ClientWrapper, userID uint64, keyID string, output string) error {
	if userID == 0 {
		return fmt.Errorf("user ID cannot be zero")
	}
	
	if keyID == "" {
		return fmt.Errorf("preauth key ID cannot be empty")
	}
	
	// Get all preauth keys for the user and check if the key exists
	response, err := client.ListPreAuthKeys(nil, &v1.ListPreAuthKeysRequest{User: userID})
	if err != nil {
		return fmt.Errorf("failed to list preauth keys: %w", err)
	}
	
	for _, key := range response.GetPreAuthKeys() {
		if key.GetKey() == keyID {
			return nil // Key exists
		}
	}
	
	return fmt.Errorf("preauth key with ID '%s' does not exist for user %d", keyID, userID)
}

// Advanced validation helpers

// ValidateNoDuplicateUsers validates that a username is not already taken
func ValidateNoDuplicateUsers(client *ClientWrapper, userName string, excludeUserID uint64) error {
	if userName == "" {
		return fmt.Errorf("username cannot be empty")
	}
	
	response, err := client.ListUsers(nil, &v1.ListUsersRequest{})
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}
	
	for _, user := range response.GetUsers() {
		if user.GetName() == userName && user.GetId() != excludeUserID {
			return fmt.Errorf("user with name '%s' already exists", userName)
		}
	}
	
	return nil
}

// ValidateNoDuplicateNodes validates that a node name is not already taken
func ValidateNoDuplicateNodes(client *ClientWrapper, nodeName string, excludeNodeID uint64) error {
	if nodeName == "" {
		return fmt.Errorf("node name cannot be empty")
	}
	
	response, err := client.ListNodes(nil, &v1.ListNodesRequest{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}
	
	for _, node := range response.GetNodes() {
		if node.GetName() == nodeName && node.GetId() != excludeNodeID {
			return fmt.Errorf("node with name '%s' already exists", nodeName)
		}
	}
	
	return nil
}

// ValidateUserOwnsNode validates that a user owns a specific node
func ValidateUserOwnsNode(client *ClientWrapper, userID uint64, nodeID uint64) error {
	if userID == 0 {
		return fmt.Errorf("user ID cannot be zero")
	}
	
	if nodeID == 0 {
		return fmt.Errorf("node ID cannot be zero")
	}
	
	response, err := client.GetNode(nil, &v1.GetNodeRequest{NodeId: nodeID})
	if err != nil {
		return fmt.Errorf("failed to get node: %w", err)
	}
	
	if response.GetNode().GetUser().GetId() != userID {
		return fmt.Errorf("node %d is not owned by user %d", nodeID, userID)
	}
	
	return nil
}

// Policy validation helpers

// ValidatePolicyJSON validates that a policy string is valid JSON
func ValidatePolicyJSON(policy string) error {
	if policy == "" {
		return fmt.Errorf("policy cannot be empty")
	}
	
	// Basic JSON syntax validation could be added here
	// For now, we'll do a simple check for basic JSON structure
	policy = strings.TrimSpace(policy)
	if !strings.HasPrefix(policy, "{") || !strings.HasSuffix(policy, "}") {
		return fmt.Errorf("policy must be valid JSON object")
	}
	
	return nil
}

// Utility validation helpers

// ValidatePositiveInteger validates that a value is a positive integer
func ValidatePositiveInteger(value int64, fieldName string) error {
	if value <= 0 {
		return fmt.Errorf("%s must be a positive integer, got %d", fieldName, value)
	}
	return nil
}

// ValidateNonNegativeInteger validates that a value is a non-negative integer
func ValidateNonNegativeInteger(value int64, fieldName string) error {
	if value < 0 {
		return fmt.Errorf("%s must be non-negative, got %d", fieldName, value)
	}
	return nil
}

// ValidateStringLength validates that a string is within specified length bounds
func ValidateStringLength(value string, fieldName string, minLength, maxLength int) error {
	if len(value) < minLength {
		return fmt.Errorf("%s must be at least %d characters long, got %d", fieldName, minLength, len(value))
	}
	if len(value) > maxLength {
		return fmt.Errorf("%s cannot be longer than %d characters, got %d", fieldName, maxLength, len(value))
	}
	return nil
}

// ValidateOneOf validates that a value is one of the allowed values
func ValidateOneOf(value string, fieldName string, allowedValues []string) error {
	for _, allowed := range allowedValues {
		if value == allowed {
			return nil
		}
	}
	return fmt.Errorf("%s must be one of: %s, got '%s'", fieldName, strings.Join(allowedValues, ", "), value)
}