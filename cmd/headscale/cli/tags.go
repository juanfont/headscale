package cli

import (
	"fmt"
	"log"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(tagCmd)

	addTagCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err := addTagCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	addTagCmd.Flags().
		StringSliceP("tags", "t", []string{}, "List of tags to add to the node")
	tagCmd.AddCommand(addTagCmd)

	delTagCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = delTagCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	delTagCmd.Flags().
		StringSliceP("tags", "t", []string{}, "List of tags to remove from the node")
	tagCmd.AddCommand(delTagCmd)
}

var tagCmd = &cobra.Command{
	Use:     "tags",
	Short:   "Manage the tags of Headscale",
	Aliases: []string{"t", "tag"},
}

var addTagCmd = &cobra.Command{
	Use:   "add",
	Short: "Add tags to a node in your network",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		// retrieve flags from CLI
		identifier, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error converting ID to integer: %s", err),
				output,
			)

			return
		}
		tagsToAdd, err := cmd.Flags().GetStringSlice("tags")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving list of tags to add to machine, %v", err),
				output,
			)

			return
		}

		// retrieve machine informations
		request := &v1.GetMachineRequest{
			MachineId: identifier,
		}
		resp, err := client.GetMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving machine: %s", err),
				output,
			)
		}

		// update machine
		mergedTags := resp.Machine.GetForcedTags()
		for _, tag := range tagsToAdd {
			if !containsString(mergedTags, tag) {
				mergedTags = append(mergedTags, tag)
			}
		}

		machine := resp.GetMachine()
		machine.ForcedTags = mergedTags

		updateReq := &v1.UpdateMachineRequest{
			Machine: machine,
		}

		// send updated machine upstream
		updateResponse, err := client.UpdateMachine(ctx, updateReq)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error while updating machine: %s", err),
				output,
			)
		}

		if updateResponse != nil {
			SuccessOutput(
				updateResponse.GetMachine(),
				"Machine updated",
				output,
			)
		}
	},
}

var delTagCmd = &cobra.Command{
	Use:     "del",
	Short:   "remove tags to a node in your network",
	Aliases: []string{"remove", "rm"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		// retrieve flags from CLI
		identifier, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error converting ID to integer: %s", err),
				output,
			)

			return
		}
		tagsToRemove, err := cmd.Flags().GetStringSlice("tags")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving list of tags to add to machine: %v", err),
				output,
			)

			return
		}

		// retrieve machine informations
		request := &v1.GetMachineRequest{
			MachineId: identifier,
		}
		resp, err := client.GetMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving machine: %s", err),
				output,
			)
		}

		// update machine
		keepTags := resp.Machine.GetForcedTags()
		for _, tag := range tagsToRemove {
			for i, t := range keepTags {
				if t == tag {
					keepTags = append(keepTags[:i], keepTags[i+1:]...)
				}
			}
		}

		machine := resp.GetMachine()
		machine.ForcedTags = keepTags

		updateReq := &v1.UpdateMachineRequest{
			Machine: machine,
		}

		// send updated machine upstream
		updateResponse, err := client.UpdateMachine(ctx, updateReq)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error while updating machine: %s", err),
				output,
			)
		}

		if updateResponse != nil {
			SuccessOutput(
				updateResponse.GetMachine(),
				"Machine updated",
				output,
			)
		}
	},
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}

	return false
}
