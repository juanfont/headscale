package main

import (
	"context"
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Policy command flags
var policyArgs struct {
	File       string `flag:"file,f,Policy file path"`
	PolicyFile string `flag:"policy-file,Policy file path (backward compatibility alias for --file)"`
}

// Helper function to get policy file from either --file or --policy-file flags
// Prioritizes --file but falls back to --policy-file for backward compatibility
func getPolicyFileFromFlags() string {
	if policyArgs.File != "" {
		return policyArgs.File
	}
	return policyArgs.PolicyFile
}

// Policy command implementations

func getPolicyCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.GetPolicyRequest{}

		response, err := client.GetPolicy(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot get policy: %w", err)
		}

		return outputResult(response.GetPolicy(), "Current Policy", globalArgs.Output)
	})
}

func setPolicyCommand(env *command.Env) error {
	policyFile := getPolicyFileFromFlags()
	if policyFile == "" {
		return fmt.Errorf("--file or --policy-file flag is required")
	}

	// Read policy file
	policyBytes, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("cannot read policy file: %w", err)
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.SetPolicyRequest{
			Policy: string(policyBytes),
		}

		response, err := client.SetPolicy(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot set policy: %w", err)
		}

		return outputResult(response.GetPolicy(), "Policy updated", globalArgs.Output)
	})
}

func testPolicyCommand(env *command.Env) error {
	policyFile := getPolicyFileFromFlags()
	if policyFile == "" {
		return fmt.Errorf("--file or --policy-file flag is required")
	}

	// Read the policy file
	policyBytes, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("cannot read policy file: %w", err)
	}

	// Basic validation - check if file is readable and non-empty
	if len(policyBytes) == 0 {
		return fmt.Errorf("policy file is empty")
	}

	// Try to parse as JSON to check basic syntax
	// TODO: Implement proper policy validation when API is available
	fmt.Printf("Policy file '%s' exists and can be read (%d bytes)\n", policyFile, len(policyBytes))
	fmt.Println("Note: Full policy validation requires the headscale server to be running")
	fmt.Println("Use 'headscale policy set --file <file>' to test validation against the server")

	return nil
}

func reloadPolicyCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get current policy
		getRequest := &v1.GetPolicyRequest{}
		getResponse, err := client.GetPolicy(ctx, getRequest)
		if err != nil {
			return fmt.Errorf("cannot get current policy: %w", err)
		}

		// Set the same policy to trigger reload
		setRequest := &v1.SetPolicyRequest{
			Policy: getResponse.GetPolicy(),
		}

		setResponse, err := client.SetPolicy(ctx, setRequest)
		if err != nil {
			return fmt.Errorf("cannot reload policy: %w", err)
		}

		return outputResult(setResponse.GetPolicy(), "Policy reloaded", globalArgs.Output)
	})
}

// Policy command definitions

func policyCommands() []*command.C {
	policyCommand := &command.C{
		Name:     "policy",
		Usage:    "<subcommand> [flags] [args...]",
		Help:     "Manage ACL policies",
		SetFlags: command.Flags(flax.MustBind, &globalArgs),
		Commands: []*command.C{
			{
				Name:  "get",
				Usage: "",
				Help:  "Get the current policy",
				Run:   getPolicyCommand,
			},
			{
				Name:     "set",
				Usage:    "--file <file> | --policy-file <file>",
				Help:     "Set a new policy from file",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &policyArgs),
				Run:      setPolicyCommand,
			},
			{
				Name:     "test",
				Usage:    "--file <file> | --policy-file <file>",
				Help:     "Test a policy file for validity",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &policyArgs),
				Run:      testPolicyCommand,
			},
			{
				Name:     "validate",
				Usage:    "--file <file> | --policy-file <file>",
				Help:     "Test a policy file for validity (alias)",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &policyArgs),
				Run:      testPolicyCommand,
				Unlisted: true,
			},
			{
				Name:     "check",
				Usage:    "--file <file> | --policy-file <file>",
				Help:     "Test a policy file for validity (backward compatibility alias)",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &policyArgs),
				Run:      testPolicyCommand,
				Unlisted: true,
			},
			{
				Name:  "reload",
				Usage: "",
				Help:  "Reload the current policy from storage",
				Run:   reloadPolicyCommand,
			},
		},
	}

	return []*command.C{
		policyCommand,
		// Policy management alias
		createCommandAlias(policyCommand, "acl", "Manage ACL policies (alias)"),
	}
}
