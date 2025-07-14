package cli

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasMachineOutputFlag(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected bool
	}{
		{
			name:     "no machine output flags",
			args:     []string{"headscale", "users", "list"},
			expected: false,
		},
		{
			name:     "json flag present",
			args:     []string{"headscale", "users", "list", "json"},
			expected: true,
		},
		{
			name:     "json-line flag present",
			args:     []string{"headscale", "nodes", "list", "json-line"},
			expected: true,
		},
		{
			name:     "yaml flag present",
			args:     []string{"headscale", "apikeys", "list", "yaml"},
			expected: true,
		},
		{
			name:     "mixed flags with json",
			args:     []string{"headscale", "--config", "/tmp/config.yaml", "users", "list", "json"},
			expected: true,
		},
		{
			name:     "flag as part of longer argument",
			args:     []string{"headscale", "users", "create", "json-user@example.com"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original os.Args
			originalArgs := os.Args
			defer func() { os.Args = originalArgs }()

			// Set os.Args to test case
			os.Args = tt.args

			result := HasMachineOutputFlag()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOutput(t *testing.T) {
	tests := []struct {
		name         string
		result       interface{}
		override     string
		outputFormat string
		expected     string
	}{
		{
			name:         "default format returns override",
			result:       map[string]string{"test": "value"},
			override:     "Human readable output",
			outputFormat: "",
			expected:     "Human readable output",
		},
		{
			name:         "default format with empty override",
			result:       map[string]string{"test": "value"},
			override:     "",
			outputFormat: "",
			expected:     "",
		},
		{
			name:         "json format",
			result:       map[string]string{"name": "test", "id": "123"},
			override:     "Human readable",
			outputFormat: "json",
			expected:     "{\n\t\"id\": \"123\",\n\t\"name\": \"test\"\n}",
		},
		{
			name:         "json-line format",
			result:       map[string]string{"name": "test", "id": "123"},
			override:     "Human readable",
			outputFormat: "json-line",
			expected:     "{\"id\":\"123\",\"name\":\"test\"}",
		},
		{
			name:         "yaml format",
			result:       map[string]string{"name": "test", "id": "123"},
			override:     "Human readable",
			outputFormat: "yaml",
			expected:     "id: \"123\"\nname: test\n",
		},
		{
			name:         "invalid format returns override",
			result:       map[string]string{"test": "value"},
			override:     "Human readable output",
			outputFormat: "invalid",
			expected:     "Human readable output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := output(tt.result, tt.override, tt.outputFormat)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOutputWithComplexData(t *testing.T) {
	// Test with more complex data structures
	complexData := struct {
		Users []struct {
			Name string `json:"name" yaml:"name"`
			ID   int    `json:"id" yaml:"id"`
		} `json:"users" yaml:"users"`
	}{
		Users: []struct {
			Name string `json:"name" yaml:"name"`
			ID   int    `json:"id" yaml:"id"`
		}{
			{Name: "user1", ID: 1},
			{Name: "user2", ID: 2},
		},
	}

	// Test JSON output
	jsonResult := output(complexData, "override", "json")
	assert.Contains(t, jsonResult, "\"users\":")
	assert.Contains(t, jsonResult, "\"name\": \"user1\"")
	assert.Contains(t, jsonResult, "\"id\": 1")

	// Test YAML output
	yamlResult := output(complexData, "override", "yaml")
	assert.Contains(t, yamlResult, "users:")
	assert.Contains(t, yamlResult, "name: user1")
	assert.Contains(t, yamlResult, "id: 1")
}

func TestOutputWithNilData(t *testing.T) {
	// Test with nil data
	result := output(nil, "fallback", "json")
	assert.Equal(t, "null", result)

	result = output(nil, "fallback", "yaml")
	assert.Equal(t, "null\n", result)

	result = output(nil, "fallback", "")
	assert.Equal(t, "fallback", result)
}

func TestOutputWithEmptyData(t *testing.T) {
	// Test with empty slice
	emptySlice := []string{}
	result := output(emptySlice, "fallback", "json")
	assert.Equal(t, "[]", result)

	// Test with empty map
	emptyMap := map[string]string{}
	result = output(emptyMap, "fallback", "json")
	assert.Equal(t, "{}", result)
}