package cli

import (
	"fmt"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOutputManager(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	
	om := NewOutputManager(cmd)
	
	assert.NotNil(t, om)
	assert.Equal(t, cmd, om.cmd)
	assert.Equal(t, "", om.outputFormat) // Default empty format
}

func TestOutputManager_HasMachineOutput(t *testing.T) {
	tests := []struct {
		name           string
		outputFormat   string
		expectedResult bool
	}{
		{
			name:           "empty format (human readable)",
			outputFormat:   "",
			expectedResult: false,
		},
		{
			name:           "json format",
			outputFormat:   "json",
			expectedResult: true,
		},
		{
			name:           "yaml format", 
			outputFormat:   "yaml",
			expectedResult: true,
		},
		{
			name:           "json-line format",
			outputFormat:   "json-line",
			expectedResult: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			AddOutputFlag(cmd)
			
			if tt.outputFormat != "" {
				err := cmd.Flags().Set("output", tt.outputFormat)
				require.NoError(t, err)
			}
			
			om := NewOutputManager(cmd)
			result := om.HasMachineOutput()
			
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestNewTableRenderer(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	om := NewOutputManager(cmd)
	
	tr := NewTableRenderer(om)
	
	assert.NotNil(t, tr)
	assert.Equal(t, om, tr.outputManager)
	assert.Empty(t, tr.columns)
	assert.Empty(t, tr.data)
}

func TestTableRenderer_AddColumn(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	om := NewOutputManager(cmd)
	tr := NewTableRenderer(om)
	
	extractFunc := func(item interface{}) string {
		return "test"
	}
	
	result := tr.AddColumn("Test Header", extractFunc)
	
	// Should return self for chaining
	assert.Equal(t, tr, result)
	
	// Should have added column
	require.Len(t, tr.columns, 1)
	assert.Equal(t, "Test Header", tr.columns[0].Header)
	assert.NotNil(t, tr.columns[0].Extract)
	assert.Nil(t, tr.columns[0].Color)
}

func TestTableRenderer_AddColoredColumn(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	om := NewOutputManager(cmd)
	tr := NewTableRenderer(om)
	
	extractFunc := func(item interface{}) string {
		return "test"
	}
	
	colorFunc := func(value string) string {
		return ColorGreen(value)
	}
	
	result := tr.AddColoredColumn("Colored Header", extractFunc, colorFunc)
	
	// Should return self for chaining
	assert.Equal(t, tr, result)
	
	// Should have added colored column
	require.Len(t, tr.columns, 1)
	assert.Equal(t, "Colored Header", tr.columns[0].Header)
	assert.NotNil(t, tr.columns[0].Extract)
	assert.NotNil(t, tr.columns[0].Color)
}

func TestTableRenderer_SetData(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	om := NewOutputManager(cmd)
	tr := NewTableRenderer(om)
	
	testData := []interface{}{"item1", "item2", "item3"}
	
	result := tr.SetData(testData)
	
	// Should return self for chaining
	assert.Equal(t, tr, result)
	
	// Should have set data
	assert.Equal(t, testData, tr.data)
}

func TestTableRenderer_Chaining(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	om := NewOutputManager(cmd)
	
	testData := []interface{}{"item1", "item2"}
	
	// Test method chaining
	tr := NewTableRenderer(om).
		AddColumn("Column1", func(item interface{}) string { return "col1" }).
		AddColoredColumn("Column2", func(item interface{}) string { return "col2" }, ColorGreen).
		SetData(testData)
	
	assert.NotNil(t, tr)
	assert.Len(t, tr.columns, 2)
	assert.Equal(t, testData, tr.data)
}

func TestColorFunctions(t *testing.T) {
	testText := "test"
	
	// Test that color functions return non-empty strings
	// We can't test exact output since pterm formatting depends on terminal
	assert.NotEmpty(t, ColorGreen(testText))
	assert.NotEmpty(t, ColorRed(testText))
	assert.NotEmpty(t, ColorYellow(testText))
	assert.NotEmpty(t, ColorMagenta(testText))
	assert.NotEmpty(t, ColorBlue(testText))
	assert.NotEmpty(t, ColorCyan(testText))
	
	// Test that color functions actually modify the input
	assert.NotEqual(t, testText, ColorGreen(testText))
	assert.NotEqual(t, testText, ColorRed(testText))
}

func TestFormatTime(t *testing.T) {
	tests := []struct {
		name     string
		time     time.Time
		expected string
	}{
		{
			name:     "zero time",
			time:     time.Time{},
			expected: "N/A",
		},
		{
			name:     "specific time",
			time:     time.Date(2023, 12, 25, 15, 30, 45, 0, time.UTC),
			expected: "2023-12-25 15:30:45",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatTime(tt.time)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatTimeColored(t *testing.T) {
	now := time.Now()
	futureTime := now.Add(time.Hour)
	pastTime := now.Add(-time.Hour)
	
	// Test zero time
	result := FormatTimeColored(time.Time{})
	assert.Equal(t, "N/A", result)
	
	// Test future time (should be green)
	futureResult := FormatTimeColored(futureTime)
	assert.Contains(t, futureResult, futureTime.Format(HeadscaleDateTimeFormat))
	assert.NotEqual(t, futureTime.Format(HeadscaleDateTimeFormat), futureResult) // Should be colored
	
	// Test past time (should be red)
	pastResult := FormatTimeColored(pastTime)
	assert.Contains(t, pastResult, pastTime.Format(HeadscaleDateTimeFormat))
	assert.NotEqual(t, pastTime.Format(HeadscaleDateTimeFormat), pastResult) // Should be colored
}

func TestFormatBool(t *testing.T) {
	assert.Equal(t, "true", FormatBool(true))
	assert.Equal(t, "false", FormatBool(false))
}

func TestFormatBoolColored(t *testing.T) {
	trueResult := FormatBoolColored(true)
	falseResult := FormatBoolColored(false)
	
	// Should contain the boolean value
	assert.Contains(t, trueResult, "true")
	assert.Contains(t, falseResult, "false")
	
	// Should be colored (different from plain text)
	assert.NotEqual(t, "true", trueResult)
	assert.NotEqual(t, "false", falseResult)
}

func TestFormatYesNo(t *testing.T) {
	assert.Equal(t, "Yes", FormatYesNo(true))
	assert.Equal(t, "No", FormatYesNo(false))
}

func TestFormatYesNoColored(t *testing.T) {
	yesResult := FormatYesNoColored(true)
	noResult := FormatYesNoColored(false)
	
	// Should contain the yes/no value
	assert.Contains(t, yesResult, "Yes")
	assert.Contains(t, noResult, "No")
	
	// Should be colored
	assert.NotEqual(t, "Yes", yesResult)
	assert.NotEqual(t, "No", noResult)
}

func TestFormatOnlineStatus(t *testing.T) {
	onlineResult := FormatOnlineStatus(true)
	offlineResult := FormatOnlineStatus(false)
	
	assert.Contains(t, onlineResult, "online")
	assert.Contains(t, offlineResult, "offline")
	
	// Should be colored
	assert.NotEqual(t, "online", onlineResult)
	assert.NotEqual(t, "offline", offlineResult)
}

func TestFormatExpiredStatus(t *testing.T) {
	expiredResult := FormatExpiredStatus(true)
	notExpiredResult := FormatExpiredStatus(false)
	
	assert.Contains(t, expiredResult, "yes")
	assert.Contains(t, notExpiredResult, "no")
	
	// Should be colored
	assert.NotEqual(t, "yes", expiredResult)
	assert.NotEqual(t, "no", notExpiredResult)
}

func TestFormatStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		expected string
	}{
		{
			name:     "empty slice",
			slice:    []string{},
			expected: "",
		},
		{
			name:     "single item",
			slice:    []string{"item1"},
			expected: "item1",
		},
		{
			name:     "multiple items",
			slice:    []string{"item1", "item2", "item3"},
			expected: "item1, item2, item3",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatStringSlice(tt.slice)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatTagList(t *testing.T) {
	tests := []struct {
		name      string
		tags      []string
		colorFunc func(string) string
		expected  string
	}{
		{
			name:      "empty tags",
			tags:      []string{},
			colorFunc: nil,
			expected:  "",
		},
		{
			name:      "single tag without color",
			tags:      []string{"tag1"},
			colorFunc: nil,
			expected:  "tag1",
		},
		{
			name:      "multiple tags without color",
			tags:      []string{"tag1", "tag2"},
			colorFunc: nil,
			expected:  "tag1, tag2",
		},
		{
			name:      "tags with color function",
			tags:      []string{"tag1", "tag2"},
			colorFunc: func(s string) string { return "[" + s + "]" }, // Mock color function
			expected:  "[tag1], [tag2]",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatTagList(tt.tags, tt.colorFunc)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractStringField(t *testing.T) {
	// Test basic functionality
	result := ExtractStringField("test string", "field")
	assert.Equal(t, "test string", result)
	
	// Test with number
	result = ExtractStringField(123, "field")
	assert.Equal(t, "123", result)
	
	// Test with boolean
	result = ExtractStringField(true, "field")
	assert.Equal(t, "true", result)
}

func TestOutputManagerIntegration(t *testing.T) {
	// Test integration between OutputManager and other components
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	
	// Test with different output formats
	formats := []string{"", "json", "yaml", "json-line"}
	
	for _, format := range formats {
		t.Run("format_"+format, func(t *testing.T) {
			if format != "" {
				err := cmd.Flags().Set("output", format)
				require.NoError(t, err)
			}
			
			om := NewOutputManager(cmd)
			
			// Verify output format detection
			expectedHasMachine := format != ""
			assert.Equal(t, expectedHasMachine, om.HasMachineOutput())
			
			// Test table renderer creation
			tr := NewTableRenderer(om)
			assert.NotNil(t, tr)
			assert.Equal(t, om, tr.outputManager)
		})
	}
}

func TestTableRendererCompleteWorkflow(t *testing.T) {
	// Test complete table rendering workflow
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	
	om := NewOutputManager(cmd)
	
	// Mock data
	type TestItem struct {
		ID   int
		Name string
		Active bool
	}
	
	testData := []interface{}{
		TestItem{ID: 1, Name: "Item1", Active: true},
		TestItem{ID: 2, Name: "Item2", Active: false},
	}
	
	// Create and configure table
	tr := NewTableRenderer(om).
		AddColumn("ID", func(item interface{}) string {
			if testItem, ok := item.(TestItem); ok {
				return FormatStringField(testItem.ID)
			}
			return ""
		}).
		AddColumn("Name", func(item interface{}) string {
			if testItem, ok := item.(TestItem); ok {
				return testItem.Name
			}
			return ""
		}).
		AddColoredColumn("Status", func(item interface{}) string {
			if testItem, ok := item.(TestItem); ok {
				return FormatYesNo(testItem.Active)
			}
			return ""
		}, func(value string) string {
			if value == "Yes" {
				return ColorGreen(value)
			}
			return ColorRed(value)
		}).
		SetData(testData)
	
	// Verify configuration
	assert.Len(t, tr.columns, 3)
	assert.Equal(t, testData, tr.data)
	assert.Equal(t, "ID", tr.columns[0].Header)
	assert.Equal(t, "Name", tr.columns[1].Header)
	assert.Equal(t, "Status", tr.columns[2].Header)
}

// Helper function for tests
func FormatStringField(value interface{}) string {
	return fmt.Sprintf("%v", value)
}