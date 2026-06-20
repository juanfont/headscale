package apiv2

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerSettings)
}

// TailnetSettings is the Tailscale tailnet-settings response. Headscale's config
// is file-based and mostly not runtime-mutable, so only a few fields carry a
// real value; the rest report the honest "off"/default.
type TailnetSettings struct {
	ACLsExternallyManagedOn bool   `json:"aclsExternallyManagedOn"`
	ACLsExternalLink        string `json:"aclsExternalLink"`

	DevicesApprovalOn      bool `json:"devicesApprovalOn"`
	DevicesAutoUpdatesOn   bool `json:"devicesAutoUpdatesOn"`
	DevicesKeyDurationDays int  `json:"devicesKeyDurationDays"`

	UsersApprovalOn                        bool   `json:"usersApprovalOn"`
	UsersRoleAllowedToJoinExternalTailnets string `json:"usersRoleAllowedToJoinExternalTailnets"`

	NetworkFlowLoggingOn        bool `json:"networkFlowLoggingOn"`
	RegionalRoutingOn           bool `json:"regionalRoutingOn"`
	PostureIdentityCollectionOn bool `json:"postureIdentityCollectionOn"`
	HTTPSEnabled                bool `json:"httpsEnabled"`
}

type (
	getSettingsInput struct {
		Tailnet string `path:"tailnet"`
	}
	settingsOutput struct {
		Body TailnetSettings
	}
	patchSettingsInput struct {
		Tailnet string `path:"tailnet"`
		// Accepted and ignored; updating settings is not supported.
		Body json.RawMessage
	}
)

func registerSettings(api huma.API, b Backend) {
	settingsTags := []string{"TailnetSettings", "Tailscale compat"}

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "getTailnetSettings",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/settings",
		Summary:     "Get tailnet settings",
		Tags:        settingsTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, ScopeFeatureSettingsRead), func(ctx context.Context, in *getSettingsInput) (*settingsOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		cfg := b.Cfg

		return &settingsOutput{Body: TailnetSettings{
			// File-mode policy is genuinely externally managed (read-only via API).
			ACLsExternallyManagedOn:                cfg.Policy.Mode == types.PolicyModeFile,
			DevicesKeyDurationDays:                 int(cfg.Node.Expiry / (24 * time.Hour)),
			HTTPSEnabled:                           cfg.TLS.CertPath != "" || cfg.TLS.LetsEncrypt.Hostname != "",
			UsersRoleAllowedToJoinExternalTailnets: "none",
		}}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "updateTailnetSettings",
		Method:      http.MethodPatch,
		Path:        "/api/v2/tailnet/{tailnet}/settings",
		Summary:     "Update tailnet settings",
		Tags:        settingsTags,
		Security:    security,
		// The body is accepted but ignored; skip validation.
		SkipValidateBody: true,
		Errors:           []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusNotImplemented},
	}, ScopeFeatureSettings), func(ctx context.Context, in *patchSettingsInput) (*settingsOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		return nil, huma.Error501NotImplemented(
			"updating tailnet settings is not supported by Headscale",
		)
	})
}
