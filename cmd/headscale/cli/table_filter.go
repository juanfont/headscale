package cli

import (
	"strings"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

const (
	deprecateNamespaceMessage = "use --user"
	HeadscaleDateTimeFormat   = "2006-01-02 15:04:05"
)

// FilterTableColumns filters table columns based on --columns flag
func FilterTableColumns(cmd *cobra.Command, tableData pterm.TableData) pterm.TableData {
	columns, _ := cmd.Flags().GetString("columns")
	if columns == "" || len(tableData) == 0 {
		return tableData
	}

	headers := tableData[0]
	wantedColumns := strings.Split(columns, ",")
	
	// Find column indices
	var indices []int
	for _, wanted := range wantedColumns {
		wanted = strings.TrimSpace(wanted)
		for i, header := range headers {
			if strings.EqualFold(header, wanted) {
				indices = append(indices, i)
				break
			}
		}
	}

	if len(indices) == 0 {
		return tableData
	}

	// Filter all rows
	filtered := make(pterm.TableData, len(tableData))
	for i, row := range tableData {
		newRow := make([]string, len(indices))
		for j, idx := range indices {
			if idx < len(row) {
				newRow[j] = row[idx]
			}
		}
		filtered[i] = newRow
	}

	return filtered
}