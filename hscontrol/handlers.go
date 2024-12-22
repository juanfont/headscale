package hscontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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

	// TODO(juan): remove this once https://github.com/juanfont/headscale/issues/727 is fixed.
	registrationHoldoff        = time.Second * 5
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
	writer io.Writer,
) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("cannot read request body: %w", err)
	}

	var derpAdmitClientRequest tailcfg.DERPAdmitClientRequest
	if err := json.Unmarshal(body, &derpAdmitClientRequest); err != nil {
		return fmt.Errorf("cannot parse derpAdmitClientRequest: %w", err)
	}

	nodes, err := h.db.ListNodes()
	if err != nil {
		return fmt.Errorf("cannot list nodes: %w", err)
	}

	resp := &tailcfg.DERPAdmitClientResponse{
		Allow: nodes.ContainsNodeKey(derpAdmitClientRequest.NodePublic),
	}
	if err = json.NewEncoder(writer).Encode(resp); err != nil {
		return fmt.Errorf("cannot encode response: %w", err)
	}

	return nil
}

// VerifyHandler see https://github.com/tailscale/tailscale/blob/964282d34f06ecc06ce644769c66b0b31d118340/derp/derp_server.go#L1159,
// DERP use verifyClientsURL to verify whether a client is allowed to connect to the DERP server.
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

	if err := h.handleVerifyRequest(req, writer); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to verify client")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
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

func registerWebHTML(key string) *elem.Element {
	return elem.Html(nil,
		elem.Head(
			nil,
			elem.Title(nil, elem.Text("Registration - Headscale")),
			elem.Meta(attrs.Props{
				attrs.Name:    "viewport",
				attrs.Content: "width=device-width, initial-scale=1",
			}),
		),
		elem.Body(attrs.Props{
			attrs.Style: styles.Props{
				styles.FontFamily: "sans",
			}.ToInline(),
		},
			elem.H1(nil, elem.Text("headscale")),
			elem.H2(nil, elem.Text("Machine registration")),
			elem.P(nil, elem.Text("Run the command below in the headscale server to add this machine to your network:")),
			elem.Code(attrs.Props{attrs.Style: codeStyleRegisterWebAPI.ToInline()},
				elem.Text(fmt.Sprintf("headscale nodes register --user USERNAME --key %s", key)),
			),
		),
	)
}

type AuthProviderWeb struct {
	serverURL string
}

func NewAuthProviderWeb(serverURL string) *AuthProviderWeb {
	return &AuthProviderWeb{
		serverURL: serverURL,
	}
}

func (a *AuthProviderWeb) AuthURL(mKey key.MachinePublic) string {
	return fmt.Sprintf(
		"%s/register/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		mKey.String())
}

// RegisterWebAPI shows a simple message in the browser to point to the CLI
// Listens in /register/:nkey.
//
// This is not part of the Tailscale control API, as we could send whatever URL
// in the RegisterResponse.AuthURL field.
func (a *AuthProviderWeb) RegisterHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	machineKeyStr := vars["mkey"]

	// We need to make sure we dont open for XSS style injections, if the parameter that
	// is passed as a key is not parsable/validated as a NodePublic key, then fail to render
	// the template and log an error.
	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText(
		[]byte(machineKeyStr),
	)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse incoming machinekey")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Wrong params"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write([]byte(registerWebHTML(machineKey.String()).Render())); err != nil {
		if _, err := writer.Write([]byte(templates.RegisterWeb(machineKey.String()).Render())); err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}
	}
}
