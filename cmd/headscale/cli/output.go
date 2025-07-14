package cli

import (
	"fmt"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// OutputManager handles all output formatting and rendering for CLI commands
type OutputManager struct {
	cmd          *cobra.Command
	outputFormat string
}

// NewOutputManager creates a new output manager for the given command
func NewOutputManager(cmd *cobra.Command) *OutputManager {
	return &OutputManager{
		cmd:          cmd,
		outputFormat: GetOutputFormat(cmd),
	}
}

// Success outputs successful results and exits with code 0
func (om *OutputManager) Success(data interface{}, humanMessage string) {
	SuccessOutput(data, humanMessage, om.outputFormat)
}

// Error outputs error results and exits with code 1
func (om *OutputManager) Error(err error, humanMessage string) {
	ErrorOutput(err, humanMessage, om.outputFormat)
}

// HasMachineOutput returns true if the output format requires machine-readable output
func (om *OutputManager) HasMachineOutput() bool {
	return om.outputFormat != ""
}

// Table rendering infrastructure

// TableColumn defines a table column with header and data extraction function
type TableColumn struct {
	Header   string
	Width    int // Optional width specification
	Extract  func(item interface{}) string
	Color    func(value string) string // Optional color function
}

// TableRenderer handles table rendering with consistent formatting
type TableRenderer struct {
	outputManager *OutputManager
	columns       []TableColumn
	data          []interface{}
}

// NewTableRenderer creates a new table renderer
func NewTableRenderer(om *OutputManager) *TableRenderer {
	return &TableRenderer{
		outputManager: om,
		columns:       []TableColumn{},
		data:          []interface{}{},
	}
}

// AddColumn adds a column to the table
func (tr *TableRenderer) AddColumn(header string, extract func(interface{}) string) *TableRenderer {
	tr.columns = append(tr.columns, TableColumn{
		Header:  header,
		Extract: extract,
	})
	return tr
}

// AddColoredColumn adds a column with color formatting
func (tr *TableRenderer) AddColoredColumn(header string, extract func(interface{}) string, color func(string) string) *TableRenderer {
	tr.columns = append(tr.columns, TableColumn{
		Header:  header,
		Extract: extract,
		Color:   color,
	})
	return tr
}

// SetData sets the data for the table
func (tr *TableRenderer) SetData(data []interface{}) *TableRenderer {
	tr.data = data
	return tr
}

// Render renders the table or outputs machine-readable format
func (tr *TableRenderer) Render() {
	// If machine output format is requested, output the raw data instead of table
	if tr.outputManager.HasMachineOutput() {
		tr.outputManager.Success(tr.data, "")
		return
	}

	// Build table headers
	headers := make([]string, len(tr.columns))
	for i, col := range tr.columns {
		headers[i] = col.Header
	}

	// Build table data
	tableData := pterm.TableData{headers}
	for _, item := range tr.data {
		row := make([]string, len(tr.columns))
		for i, col := range tr.columns {
			value := col.Extract(item)
			if col.Color != nil {
				value = col.Color(value)
			}
			row[i] = value
		}
		tableData = append(tableData, row)
	}

	// Render table
	err := pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
	if err != nil {
		tr.outputManager.Error(
			err,
			fmt.Sprintf("Failed to render table: %s", err),
		)
	}
}

// Predefined color functions for common use cases

// ColorGreen returns a green-colored string
func ColorGreen(text string) string {
	return pterm.LightGreen(text)
}

// ColorRed returns a red-colored string
func ColorRed(text string) string {
	return pterm.LightRed(text)
}

// ColorYellow returns a yellow-colored string
func ColorYellow(text string) string {
	return pterm.LightYellow(text)
}

// ColorMagenta returns a magenta-colored string
func ColorMagenta(text string) string {
	return pterm.LightMagenta(text)
}

// ColorBlue returns a blue-colored string
func ColorBlue(text string) string {
	return pterm.LightBlue(text)
}

// ColorCyan returns a cyan-colored string
func ColorCyan(text string) string {
	return pterm.LightCyan(text)
}

// Time formatting functions

// FormatTime formats a time with standard CLI format
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.Format(HeadscaleDateTimeFormat)
}

// FormatTimeColored formats a time with color based on whether it's in past/future
func FormatTimeColored(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	timeStr := t.Format(HeadscaleDateTimeFormat)
	if t.After(time.Now()) {
		return ColorGreen(timeStr)
	}
	return ColorRed(timeStr)
}

// Boolean formatting functions

// FormatBool formats a boolean as string
func FormatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// FormatBoolColored formats a boolean with color (green for true, red for false)
func FormatBoolColored(b bool) string {
	if b {
		return ColorGreen("true")
	}
	return ColorRed("false")
}

// FormatYesNo formats a boolean as Yes/No
func FormatYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// FormatYesNoColored formats a boolean as Yes/No with color
func FormatYesNoColored(b bool) string {
	if b {
		return ColorGreen("Yes")
	}
	return ColorRed("No")
}

// FormatOnlineStatus formats online status with appropriate colors
func FormatOnlineStatus(online bool) string {
	if online {
		return ColorGreen("online")
	}
	return ColorRed("offline")
}

// FormatExpiredStatus formats expiration status with appropriate colors
func FormatExpiredStatus(expired bool) string {
	if expired {
		return ColorRed("yes")
	}
	return ColorGreen("no")
}

// List/Slice formatting functions

// FormatStringSlice formats a string slice as comma-separated values
func FormatStringSlice(slice []string) string {
	if len(slice) == 0 {
		return ""
	}
	result := ""
	for i, item := range slice {
		if i > 0 {
			result += ", "
		}
		result += item
	}
	return result
}

// FormatTagList formats a tag slice with appropriate coloring
func FormatTagList(tags []string, colorFunc func(string) string) string {
	if len(tags) == 0 {
		return ""
	}
	result := ""
	for i, tag := range tags {
		if i > 0 {
			result += ", "
		}
		if colorFunc != nil {
			result += colorFunc(tag)
		} else {
			result += tag
		}
	}
	return result
}

// Progress and status output helpers

// OutputProgress shows progress information (doesn't exit)
func OutputProgress(message string) {
	if !HasMachineOutputFlag() {
		fmt.Printf("⏳ %s...\n", message)
	}
}

// OutputInfo shows informational message (doesn't exit)
func OutputInfo(message string) {
	if !HasMachineOutputFlag() {
		fmt.Printf("ℹ️  %s\n", message)
	}
}

// OutputWarning shows warning message (doesn't exit)
func OutputWarning(message string) {
	if !HasMachineOutputFlag() {
		fmt.Printf("⚠️  %s\n", message)
	}
}

// Data validation and extraction helpers

// ExtractStringField safely extracts a string field from interface{}
func ExtractStringField(item interface{}, fieldName string) string {
	// This would use reflection in a real implementation
	// For now, we'll rely on type assertions in the actual usage
	return fmt.Sprintf("%v", item)
}

// Command output helper combinations

// SimpleSuccess outputs a simple success message with optional data
func SimpleSuccess(cmd *cobra.Command, message string, data interface{}) {
	om := NewOutputManager(cmd)
	om.Success(data, message)
}

// SimpleError outputs a simple error message
func SimpleError(cmd *cobra.Command, err error, message string) {
	om := NewOutputManager(cmd)
	om.Error(err, message)
}

// ListOutput handles standard list output (either table or machine format)
func ListOutput(cmd *cobra.Command, data []interface{}, tableSetup func(*TableRenderer)) {
	om := NewOutputManager(cmd)
	
	if om.HasMachineOutput() {
		om.Success(data, "")
		return
	}
	
	// Create table renderer and let caller configure columns
	renderer := NewTableRenderer(om)
	renderer.SetData(data)
	tableSetup(renderer)
	renderer.Render()
}

// DetailOutput handles detailed single-item output
func DetailOutput(cmd *cobra.Command, data interface{}, humanMessage string) {
	om := NewOutputManager(cmd)
	om.Success(data, humanMessage)
}

// ConfirmationOutput handles operations that need confirmation
func ConfirmationOutput(cmd *cobra.Command, result interface{}, successMessage string) {
	om := NewOutputManager(cmd)
	
	if om.HasMachineOutput() {
		om.Success(result, "")
	} else {
		om.Success(map[string]string{"Result": successMessage}, successMessage)
	}
}