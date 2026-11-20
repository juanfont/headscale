// Stock cobra, no adapter: the smallest program that shows what cobra's own
// completion scripts do with Headscale-shaped flag values. Pinned to the
// versions in Headscale's go.mod (cobra v1.10.2, pflag v1.0.10).
package main

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func values(vals []string) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		head, cur := "", toComplete
		if i := strings.LastIndex(toComplete, ","); i >= 0 {
			head, cur = toComplete[:i+1], toComplete[i+1:]
		}
		sign := ""
		if cur != "" && (cur[0] == '-' || cur[0] == '+') {
			sign, cur = cur[:1], cur[1:]
		}
		var out []cobra.Completion
		for _, v := range vals {
			if strings.HasPrefix(v, cur) {
				out = append(out, head+sign+v)
			}
		}
		// A list value: no space after it, so the user can type the next comma.
		return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
}

func main() {
	root := &cobra.Command{Use: "headscale"}
	list := &cobra.Command{Use: "list", Run: func(*cobra.Command, []string) {}}
	nodes := &cobra.Command{Use: "nodes"}
	cols := []string{"id", "name", "last-seen"}
	list.Flags().String("columns", "", "")
	list.Flags().String("sort", "", "")
	list.Flags().String("tags", "", "")
	_ = list.RegisterFlagCompletionFunc("columns", values(cols))
	_ = list.RegisterFlagCompletionFunc("sort", values(cols))
	_ = list.RegisterFlagCompletionFunc("tags", values([]string{"tag:ci", "tag:prod"}))
	nodes.AddCommand(list)
	root.AddCommand(nodes)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
