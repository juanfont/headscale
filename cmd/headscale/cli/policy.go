package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"tailscale.com/types/views"
)

const (
	bypassFlag           = "bypass-grpc-and-access-database-directly" //nolint:gosec // not a credential
	separatorWidth       = 50
	outputFormatJSON     = "json"
	outputFormatJSONLine = "json-line"
)

func init() {
	rootCmd.AddCommand(policyCmd)

	getPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")

	err := setPolicy.MarkFlagRequired("file")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	setPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	policyCmd.AddCommand(setPolicy)

	checkPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")

	err = checkPolicy.MarkFlagRequired("file")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	policyCmd.AddCommand(checkPolicy)

	// Test command flags
	testPolicy.Flags().StringP("src", "s", "", "Source alias to test from (user, group, tag, host, or IP)")
	testPolicy.Flags().StringSliceP("accept", "a", nil, "Destinations that should be allowed (repeatable, format: host:port)")
	testPolicy.Flags().StringSliceP("deny", "d", nil, "Destinations that should be denied (repeatable, format: host:port)")
	testPolicy.Flags().StringP("proto", "p", "", "Protocol to test (tcp, udp, icmp)")
	testPolicy.Flags().StringP("file", "f", "", "Path to a JSON file with test definitions")
	testPolicy.Flags().StringP("policy-file", "", "", "Test against a proposed policy file instead of current policy")
	testPolicy.Flags().BoolP("embedded", "e", false, "Run tests embedded in the current policy")
	testPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	policyCmd.AddCommand(testPolicy)
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage the Headscale ACL Policy",
}

var getPolicy = &cobra.Command{
	Use:     "get",
	Short:   "Print the current ACL Policy",
	Aliases: []string{"show", "view", "fetch"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		var policy string

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			confirm := false

			force, _ := cmd.Flags().GetBool("force")
			if !force {
				confirm = util.YesNo("DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?")
			}

			if !confirm && !force {
				ErrorOutput(nil, "Aborting command", output)
				return
			}

			cfg, err := types.LoadServerConfig()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading config: %s", err), output)
			}

			d, err := db.NewHeadscaleDatabase(
				cfg,
				nil,
			)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to open database: %s", err), output)
			}

			pol, err := d.GetPolicy()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading Policy from database: %s", err), output)
			}

			policy = pol.Data
		} else {
			ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
			defer cancel()
			defer conn.Close()

			request := &v1.GetPolicyRequest{}

			response, err := client.GetPolicy(ctx, request)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading ACL Policy: %s", err), output)
			}

			policy = response.GetPolicy()
		}

		// TODO(pallabpain): Maybe print this better?
		// This does not pass output as we dont support yaml, json or json-line
		// output for this command. It is HuJSON already.
		SuccessOutput("", policy, "")
	},
}

var setPolicy = &cobra.Command{
	Use:   "set",
	Short: "Updates the ACL Policy",
	Long: `
	Updates the existing ACL Policy with the provided policy. The policy must be a valid HuJSON object.
	This command only works when the acl.policy_mode is set to "db", and the policy will be stored in the database.`,
	Aliases: []string{"put", "update"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		policyPath, _ := cmd.Flags().GetString("file")

		f, err := os.Open(policyPath)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error opening the policy file: %s", err), output)
		}
		defer f.Close()

		policyBytes, err := io.ReadAll(f)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error reading the policy file: %s", err), output)
		}

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			confirm := false

			force, _ := cmd.Flags().GetBool("force")
			if !force {
				confirm = util.YesNo("DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?")
			}

			if !confirm && !force {
				ErrorOutput(nil, "Aborting command", output)
				return
			}

			cfg, err := types.LoadServerConfig()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading config: %s", err), output)
			}

			d, err := db.NewHeadscaleDatabase(
				cfg,
				nil,
			)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to open database: %s", err), output)
			}

			users, err := d.ListUsers()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to load users for policy validation: %s", err), output)
			}

			_, err = policy.NewPolicyManager(policyBytes, users, views.Slice[types.NodeView]{})
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Error parsing the policy file: %s", err), output)
				return
			}

			_, err = d.SetPolicy(string(policyBytes))
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to set ACL Policy: %s", err), output)
			}
		} else {
			request := &v1.SetPolicyRequest{Policy: string(policyBytes)}

			ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
			defer cancel()
			defer conn.Close()

			if _, err := client.SetPolicy(ctx, request); err != nil { //nolint:noinlineerr
				ErrorOutput(err, fmt.Sprintf("Failed to set ACL Policy: %s", err), output)
			}
		}

		SuccessOutput(nil, "Policy updated.", "")
	},
}

var checkPolicy = &cobra.Command{
	Use:   "check",
	Short: "Check the Policy file for errors",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		policyPath, _ := cmd.Flags().GetString("file")

		f, err := os.Open(policyPath)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error opening the policy file: %s", err), output)
		}
		defer f.Close()

		policyBytes, err := io.ReadAll(f)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error reading the policy file: %s", err), output)
		}

		_, err = policy.NewPolicyManager(policyBytes, nil, views.Slice[types.NodeView]{})
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error parsing the policy file: %s", err), output)
		}

		SuccessOutput(nil, "Policy is valid", "")
	},
}

var testPolicy = &cobra.Command{
	Use:   "test",
	Short: "Test ACL rules",
	Long: `Test ACL rules to verify access between sources and destinations.

Examples:
  # Test if user can access server
  headscale policy test --src "alice@example.com" --accept "tag:server:22"

  # Test with deny rules
  headscale policy test --src "alice@" --accept "10.0.0.1:80" --deny "10.0.0.2:443"

  # Run tests from a JSON file
  headscale policy test --file tests.json

  # Run embedded tests from current policy
  headscale policy test --embedded

  # Test against a proposed policy file
  headscale policy test --src "alice@" --accept "10.0.0.1:22" --policy-file new-policy.json`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		// Collect tests from various sources
		var tests []policyv2.ACLTest

		// Get flags
		src, _ := cmd.Flags().GetString("src")
		accept, _ := cmd.Flags().GetStringSlice("accept")
		deny, _ := cmd.Flags().GetStringSlice("deny")
		proto, _ := cmd.Flags().GetString("proto")
		testFile, _ := cmd.Flags().GetString("file")
		policyFile, _ := cmd.Flags().GetString("policy-file")
		embedded, _ := cmd.Flags().GetBool("embedded")
		bypass, _ := cmd.Flags().GetBool(bypassFlag)

		// Build test from command line flags if src is provided
		if src != "" {
			tests = append(tests, policyv2.ACLTest{
				Src:    src,
				Proto:  policyv2.Protocol(proto),
				Accept: accept,
				Deny:   deny,
			})
		}

		// Load tests from file if provided
		if testFile != "" {
			fileTests, err := loadTestsFromFile(testFile)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Error loading tests from file: %s", err), output)
				return
			}
			tests = append(tests, fileTests...)
		}

		// Read policy file if provided (for testing against proposed policy)
		var policyBytes []byte
		if policyFile != "" {
			f, err := os.Open(policyFile)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Error opening policy file: %s", err), output)
				return
			}
			defer f.Close()

			policyBytes, err = io.ReadAll(f)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Error reading policy file: %s", err), output)
				return
			}
		}

		var results policyv2.ACLTestResults

		if bypass {
			results = runTestsBypass(cmd, output, tests, policyBytes, embedded)
		} else {
			results = runTestsGRPC(cmd, output, tests, policyBytes, embedded)
		}

		// Output results
		if output == outputFormatJSON || output == outputFormatJSONLine {
			SuccessOutput(results, "", output)
		} else {
			printHumanReadableResults(results)
		}
	},
}

func loadTestsFromFile(path string) ([]policyv2.ACLTest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tests []policyv2.ACLTest

	decoder := json.NewDecoder(f)

	err = decoder.Decode(&tests)
	if err != nil {
		return nil, err
	}

	return tests, nil
}

func runTestsBypass(cmd *cobra.Command, output string, tests []policyv2.ACLTest, policyBytes []byte, embedded bool) policyv2.ACLTestResults {
	confirm := false

	force, _ := cmd.Flags().GetBool("force")
	if !force {
		confirm = util.YesNo("DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?")
	}

	if !confirm && !force {
		ErrorOutput(nil, "Aborting command", output)
		return policyv2.ACLTestResults{}
	}

	cfg, err := types.LoadServerConfig()
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Failed loading config: %s", err), output)
		return policyv2.ACLTestResults{}
	}

	d, err := db.NewHeadscaleDatabase(
		cfg,
		nil,
	)
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Failed to open database: %s", err), output)
		return policyv2.ACLTestResults{}
	}

	users, err := d.ListUsers()
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Failed to load users: %s", err), output)
		return policyv2.ACLTestResults{}
	}

	nodes, err := d.ListNodes()
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Failed to load nodes: %s", err), output)
		return policyv2.ACLTestResults{}
	}

	// Convert nodes to NodeView slice
	nodeViews := make([]types.NodeView, len(nodes))
	for i, n := range nodes {
		nodeViews[i] = n.View()
	}

	// Determine which policy to test against
	var polBytes []byte
	if len(policyBytes) > 0 {
		polBytes = policyBytes
	} else {
		pol, err := d.GetPolicy()
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Failed to load policy: %s", err), output)
			return policyv2.ACLTestResults{}
		}

		polBytes = []byte(pol.Data)
	}

	pm, err := policyv2.NewPolicyManager(polBytes, users, views.SliceOf(nodeViews))
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Failed to parse policy: %s", err), output)
		return policyv2.ACLTestResults{}
	}

	// If embedded flag is set, get tests from the policy
	if embedded {
		pol := pm.Policy()
		if pol != nil && len(pol.Tests) > 0 {
			tests = append(tests, pol.Tests...)
		}
	}

	if len(tests) == 0 {
		ErrorOutput(nil, "No tests to run. Use --src, --file, or --embedded to specify tests.", output)
		return policyv2.ACLTestResults{}
	}

	return pm.RunTests(tests)
}

func runTestsGRPC(_ *cobra.Command, output string, tests []policyv2.ACLTest, policyBytes []byte, embedded bool) policyv2.ACLTestResults {
	ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
	defer cancel()
	defer conn.Close()

	// If embedded, get tests from current policy first
	if embedded {
		policyResp, err := client.GetPolicy(ctx, &v1.GetPolicyRequest{})
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Failed to get current policy: %s", err), output)
			return policyv2.ACLTestResults{}
		}

		// Parse policy to extract embedded tests
		pm, err := policyv2.NewPolicyManager([]byte(policyResp.GetPolicy()), nil, views.Slice[types.NodeView]{})
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Failed to parse policy: %s", err), output)
			return policyv2.ACLTestResults{}
		}

		pol := pm.Policy()
		if pol != nil && len(pol.Tests) > 0 {
			tests = append(tests, pol.Tests...)
		}
	}

	if len(tests) == 0 {
		ErrorOutput(nil, "No tests to run. Use --src, --file, or --embedded to specify tests.", output)
		return policyv2.ACLTestResults{}
	}

	// Convert tests to proto format
	protoTests := make([]*v1.ACLTest, len(tests))
	for i, t := range tests {
		protoTests[i] = &v1.ACLTest{
			Src:    t.Src,
			Proto:  string(t.Proto),
			Accept: t.Accept,
			Deny:   t.Deny,
		}
	}

	request := &v1.TestACLRequest{
		Tests:  protoTests,
		Policy: string(policyBytes),
	}

	response, err := client.TestACL(ctx, request)
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Failed to run ACL tests: %s", err), output)
		return policyv2.ACLTestResults{}
	}

	// Convert proto response to internal format
	results := policyv2.ACLTestResults{
		AllPassed: response.GetAllPassed(),
		Results:   make([]policyv2.ACLTestResult, len(response.GetResults())),
	}

	for i, r := range response.GetResults() {
		results.Results[i] = policyv2.ACLTestResult{
			Src:        r.GetSrc(),
			Passed:     r.GetPassed(),
			Errors:     r.GetErrors(),
			AcceptOK:   r.GetAcceptOk(),
			AcceptFail: r.GetAcceptFail(),
			DenyOK:     r.GetDenyOk(),
			DenyFail:   r.GetDenyFail(),
		}
	}

	return results
}

func printHumanReadableResults(results policyv2.ACLTestResults) {
	fmt.Println("ACL Test Results")
	fmt.Println(strings.Repeat("=", separatorWidth))
	fmt.Println()

	passedCount := 0
	totalCount := len(results.Results)

	for _, result := range results.Results {
		fmt.Printf("Source: %s\n", result.Src)
		fmt.Println()

		if len(result.Errors) > 0 {
			fmt.Println("  Errors:")

			for _, e := range result.Errors {
				fmt.Printf("    ! %s\n", e)
			}

			fmt.Println()
		}

		if len(result.AcceptOK) > 0 || len(result.AcceptFail) > 0 {
			fmt.Println("  Accept Tests:")

			for _, dest := range result.AcceptOK {
				fmt.Printf("    [PASS] %s - ALLOWED (expected)\n", dest)
			}

			for _, dest := range result.AcceptFail {
				fmt.Printf("    [FAIL] %s - DENIED (expected ALLOWED)\n", dest)
			}

			fmt.Println()
		}

		if len(result.DenyOK) > 0 || len(result.DenyFail) > 0 {
			fmt.Println("  Deny Tests:")

			for _, dest := range result.DenyOK {
				fmt.Printf("    [PASS] %s - DENIED (expected)\n", dest)
			}

			for _, dest := range result.DenyFail {
				fmt.Printf("    [FAIL] %s - ALLOWED (expected DENIED)\n", dest)
			}

			fmt.Println()
		}

		if result.Passed {
			passedCount++

			fmt.Println("  Result: PASSED")
		} else {
			fmt.Println("  Result: FAILED")
		}

		fmt.Println()
		fmt.Println(strings.Repeat("-", separatorWidth))
		fmt.Println()
	}

	// Summary
	if results.AllPassed {
		fmt.Printf("Overall: PASSED (%d/%d tests passed)\n", passedCount, totalCount)
	} else {
		fmt.Printf("Overall: FAILED (%d/%d tests passed)\n", passedCount, totalCount)
	}
}
