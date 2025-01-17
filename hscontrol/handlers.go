package hscontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/chasefleming/elem-go/styles"
	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

const (
	// The CapabilityVersion is used by Tailscale clients to indicate
	// their codebase version. Tailscale clients can communicate over TS2021
	// from CapabilityVersion 28, but we only have good support for it
	// since https://github.com/tailscale/tailscale/pull/4323 (Noise in any HTTPS port).
	//
	// Related to this change, there is https://github.com/tailscale/tailscale/pull/5379,
	// where CapabilityVersion 39 is introduced to indicate #4323 was merged.
	//
	// See also https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go
	NoiseCapabilityVersion = 39

	reservedResponseHeaderSize = 4
)

var ErrRegisterMethodCLIDoesNotSupportExpire = errors.New(
	"machines registered with CLI does not support expire",
)
var ErrNoCapabilityVersion = errors.New("no capability version set")

func parseCabailityVersion(req *http.Request) (tailcfg.CapabilityVersion, error) {
	clientCapabilityStr := req.URL.Query().Get("v")

	if clientCapabilityStr == "" {
		return 0, ErrNoCapabilityVersion
	}

	clientCapabilityVersion, err := strconv.Atoi(clientCapabilityStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse capability version: %w", err)
	}

	return tailcfg.CapabilityVersion(clientCapabilityVersion), nil
}

func (h *Headscale) handleVerifyRequest(
	req *http.Request,
) (bool, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return false, fmt.Errorf("cannot read request body: %w", err)
	}

	var derpAdmitClientRequest tailcfg.DERPAdmitClientRequest
	if err := json.Unmarshal(body, &derpAdmitClientRequest); err != nil {
		return false, fmt.Errorf("cannot parse derpAdmitClientRequest: %w", err)
	}

	nodes, err := h.db.ListNodes()
	if err != nil {
		return false, fmt.Errorf("cannot list nodes: %w", err)
	}

	return nodes.ContainsNodeKey(derpAdmitClientRequest.NodePublic), nil
}

// see https://github.com/tailscale/tailscale/blob/964282d34f06ecc06ce644769c66b0b31d118340/derp/derp_server.go#L1159, Derp use verifyClientsURL to verify whether a client is allowed to connect to the DERP server.
func (h *Headscale) VerifyHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	if req.Method != http.MethodPost {
		http.Error(writer, "Wrong method", http.StatusMethodNotAllowed)

		return
	}
	log.Debug().
		Str("handler", "/verify").
		Msg("verify client")

	allow, err := h.handleVerifyRequest(req)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to verify client")
		http.Error(writer, "Internal error", http.StatusInternalServerError)
	}

	resp := tailcfg.DERPAdmitClientResponse{
		Allow: allow,
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	err = json.NewEncoder(writer).Encode(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// KeyHandler provides the Headscale pub key
// Listens in /key.
func (h *Headscale) KeyHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	// New Tailscale clients send a 'v' parameter to indicate the CurrentCapabilityVersion
	capVer, err := parseCabailityVersion(req)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("could not get capability version")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)

		return
	}

	log.Debug().
		Str("handler", "/key").
		Int("cap_ver", int(capVer)).
		Msg("New noise client")

	// TS2021 (Tailscale v2 protocol) requires to have a different key
	if capVer >= NoiseCapabilityVersion {
		resp := tailcfg.OverTLSPublicKeyResponse{
			PublicKey: h.noisePrivateKey.Public(),
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		err = json.NewEncoder(writer).Encode(resp)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}
}

func (h *Headscale) HealthHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	respond := func(err error) {
		writer.Header().Set("Content-Type", "application/health+json; charset=utf-8")

		res := struct {
			Status string `json:"status"`
		}{
			Status: "pass",
		}

		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			log.Error().Caller().Err(err).Msg("health check failed")
			res.Status = "fail"
		}

		buf, err := json.Marshal(res)
		if err != nil {
			log.Error().Caller().Err(err).Msg("marshal failed")
		}
		_, err = writer.Write(buf)
		if err != nil {
			log.Error().Caller().Err(err).Msg("write failed")
		}
	}

	if err := h.db.PingDB(req.Context()); err != nil {
		respond(err)

		return
	}

	respond(nil)
}

var codeStyleRegisterWebAPI = styles.Props{
	styles.Display:         "block",
	styles.Padding:         "20px",
	styles.Border:          "1px solid #bbb",
	styles.BackgroundColor: "#eee",
}

type AuthProviderWeb struct {
	serverURL string
}

func NewAuthProviderWeb(serverURL string) *AuthProviderWeb {
	return &AuthProviderWeb{
		serverURL: serverURL,
	}
}

func (a *AuthProviderWeb) AuthURL(registrationId types.RegistrationID) string {
	return fmt.Sprintf(
		"%s/register/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		registrationId.String())
}

// RegisterWebAPI shows a simple message in the browser to point to the CLI
// Listens in /register/:registration_id.
//
// This is not part of the Tailscale control API, as we could send whatever URL
// in the RegisterResponse.AuthURL field.
func (a *AuthProviderWeb) RegisterHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	registrationIdStr := vars["registration_id"]

	// We need to make sure we dont open for XSS style injections, if the parameter that
	// is passed as a key is not parsable/validated as a NodePublic key, then fail to render
	// the template and log an error.
	registrationId, err := types.RegistrationIDFromString(registrationIdStr)
	if err != nil {
		http.Error(writer, "invalid registration ID", http.StatusBadRequest)
		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write([]byte(templates.RegisterWeb(registrationId).Render())); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}
