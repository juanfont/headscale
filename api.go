package headscale

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	reservedResponseHeaderSize               = 4
	RegisterMethodAuthKey                    = "authkey"
	RegisterMethodOIDC                       = "oidc"
	RegisterMethodCLI                        = "cli"
	ErrRegisterMethodCLIDoesNotSupportExpire = Error(
		"machines registered with CLI does not support expire",
	)
)

// KeyHandler provides the Headscale pub key
// Listens in /key.
func (h *Headscale) KeyHandler(ctx *gin.Context) {
	ctx.Data(
		http.StatusOK,
		"text/plain; charset=utf-8",
		[]byte(MachinePublicKeyStripPrefix(h.privateKey.Public())),
	)
}

type registerWebAPITemplateConfig struct {
	Key string
}

var registerWebAPITemplate = template.Must(
	template.New("registerweb").Parse(`<html>
	<body>
	<h1>headscale</h1>
	<p>
		Run the command below in the headscale server to add this machine to your network:
	</p>

	<p>
		<code>
			<b>headscale -n NAMESPACE nodes register --key {{.Key}}</b>
		</code>
	</p>

	</body>
	</html>`),
)

// RegisterWebAPI shows a simple message in the browser to point to the CLI
// Listens in /register.
func (h *Headscale) RegisterWebAPI(ctx *gin.Context) {
	machineKeyStr := ctx.Query("key")
	if machineKeyStr == "" {
		ctx.String(http.StatusBadRequest, "Wrong params")

		return
	}

	var content bytes.Buffer
	if err := registerWebAPITemplate.Execute(&content, registerWebAPITemplateConfig{
		Key: machineKeyStr,
	}); err != nil {
		log.Error().
			Str("func", "RegisterWebAPI").
			Err(err).
			Msg("Could not render register web API template")
		ctx.Data(
			http.StatusInternalServerError,
			"text/html; charset=utf-8",
			[]byte("Could not render register web API template"),
		)
	}

	ctx.Data(http.StatusOK, "text/html; charset=utf-8", content.Bytes())
}

// RegistrationHandler handles the actual registration process of a machine
// Endpoint /machine/:id.
func (h *Headscale) RegistrationHandler(ctx *gin.Context) {
	body, _ := io.ReadAll(ctx.Request.Body)
	machineKeyStr := ctx.Param("id")

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse machine key")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		ctx.String(http.StatusInternalServerError, "Sad!")

		return
	}
	req := tailcfg.RegisterRequest{}
	err = decode(body, &req, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot decode message")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		ctx.String(http.StatusInternalServerError, "Very sad!")

		return
	}

	now := time.Now().UTC()
	machine, err := h.GetMachineByMachineKey(machineKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Info().Str("machine", req.Hostinfo.Hostname).Msg("New machine")

		machineKeyStr := MachinePublicKeyStripPrefix(machineKey)

		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if req.Auth.AuthKey != "" {
			h.handleAuthKey(ctx, machineKey, req)

			return
		}
		hname, err := NormalizeName(
			req.Hostinfo.Hostname,
			h.cfg.OIDC.StripEmaildomain,
		)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", req.Hostinfo.Hostname).
				Err(err)
			return
		}

		// The machine did not have a key to authenticate, which means
		// that we rely on a method that calls back some how (OpenID or CLI)
		// We create the machine and then keep it around until a callback
		// happens
		newMachine := Machine{
			MachineKey: machineKeyStr,
			Name:       hname,
			NodeKey:    NodePublicKeyStripPrefix(req.NodeKey),
			LastSeen:   &now,
			Expiry:     &time.Time{},
		}

		if !req.Expiry.IsZero() {
			log.Trace().
				Caller().
				Str("machine", req.Hostinfo.Hostname).
				Time("expiry", req.Expiry).
				Msg("Non-zero expiry time requested")
			newMachine.Expiry = &req.Expiry
		}

		h.registrationCache.Set(
			machineKeyStr,
			newMachine,
			registerCacheExpiration,
		)

		h.handleMachineRegistrationNew(ctx, machineKey, req)

		return
	}

	// The machine is already registered, so we need to pass through reauth or key update.
	if machine != nil {
		// If the NodeKey stored in headscale is the same as the key presented in a registration
		// request, then we have a node that is either:
		// - Trying to log out (sending a expiry in the past)
		// - A valid, registered machine, looking for the node map
		// - Expired machine wanting to reauthenticate
		if machine.NodeKey == NodePublicKeyStripPrefix(req.NodeKey) {
			// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
			//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
			if !req.Expiry.IsZero() && req.Expiry.UTC().Before(now) {
				h.handleMachineLogOut(ctx, machineKey, *machine)

				return
			}

			// If machine is not expired, and is register, we have a already accepted this machine,
			// let it proceed with a valid registration
			if !machine.isExpired() {
				h.handleMachineValidRegistration(ctx, machineKey, *machine)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if machine.NodeKey == NodePublicKeyStripPrefix(req.OldNodeKey) &&
			!machine.isExpired() {
			h.handleMachineRefreshKey(ctx, machineKey, req, *machine)

			return
		}

		// The machine has expired
		h.handleMachineExpired(ctx, machineKey, req, *machine)

		return
	}
}

func (h *Headscale) getMapResponse(
	machineKey key.MachinePublic,
	req tailcfg.MapRequest,
	machine *Machine,
) ([]byte, error) {
	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		Msg("Creating Map response")
	node, err := machine.toNode(h.cfg.BaseDomain, h.cfg.DNSConfig, true)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Cannot convert to node")

		return nil, err
	}

	peers, err := h.getValidPeers(machine)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Cannot fetch peers")

		return nil, err
	}

	profiles := getMapResponseUserProfiles(*machine, peers)

	nodePeers, err := peers.toNodes(h.cfg.BaseDomain, h.cfg.DNSConfig, true)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Failed to convert peers to Tailscale nodes")

		return nil, err
	}

	dnsConfig := getMapResponseDNSConfig(
		h.cfg.DNSConfig,
		h.cfg.BaseDomain,
		*machine,
		peers,
	)

	resp := tailcfg.MapResponse{
		KeepAlive:    false,
		Node:         node,
		Peers:        nodePeers,
		DNSConfig:    dnsConfig,
		Domain:       h.cfg.BaseDomain,
		PacketFilter: h.aclRules,
		DERPMap:      h.DERPMap,
		UserProfiles: profiles,
	}

	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		// Interface("payload", resp).
		Msgf("Generated map response: %s", tailMapResponseToString(resp))

	var respBody []byte
	if req.Compress == "zstd" {
		src, err := json.Marshal(resp)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "getMapResponse").
				Err(err).
				Msg("Failed to marshal response for the client")

			return nil, err
		}

		encoder, _ := zstd.NewWriter(nil)
		srcCompressed := encoder.EncodeAll(src, nil)
		respBody = h.privateKey.SealTo(machineKey, srcCompressed)
	} else {
		respBody, err = encode(resp, &machineKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	}
	// declare the incoming size on the first 4 bytes
	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func (h *Headscale) getMapKeepAliveResponse(
	machineKey key.MachinePublic,
	mapRequest tailcfg.MapRequest,
) ([]byte, error) {
	mapResponse := tailcfg.MapResponse{
		KeepAlive: true,
	}
	var respBody []byte
	var err error
	if mapRequest.Compress == "zstd" {
		src, err := json.Marshal(mapResponse)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "getMapKeepAliveResponse").
				Err(err).
				Msg("Failed to marshal keepalive response for the client")

			return nil, err
		}
		encoder, _ := zstd.NewWriter(nil)
		srcCompressed := encoder.EncodeAll(src, nil)
		respBody = h.privateKey.SealTo(machineKey, srcCompressed)
	} else {
		respBody, err = encode(mapResponse, &machineKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	}
	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func (h *Headscale) handleMachineLogOut(
	ctx *gin.Context,
	machineKey key.MachinePublic,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Str("machine", machine.Name).
		Msg("Client requested logout")

	h.ExpireMachine(&machine)

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.User = *machine.Namespace.toUser()
	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot encode message")
		ctx.String(http.StatusInternalServerError, "")

		return
	}
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
}

func (h *Headscale) handleMachineValidRegistration(
	ctx *gin.Context,
	machineKey key.MachinePublic,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is valid, respond with redirect to /map
	log.Debug().
		Str("machine", machine.Name).
		Msg("Client is registered and we have the current NodeKey. All clear to /map")

	resp.AuthURL = ""
	resp.MachineAuthorized = true
	resp.User = *machine.Namespace.toUser()
	resp.Login = *machine.Namespace.toLogin()

	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("update", "web", "error", machine.Namespace.Name).
			Inc()
		ctx.String(http.StatusInternalServerError, "")

		return
	}
	machineRegistrations.WithLabelValues("update", "web", "success", machine.Namespace.Name).
		Inc()
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
}

func (h *Headscale) handleMachineExpired(
	ctx *gin.Context,
	machineKey key.MachinePublic,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	// The client has registered before, but has expired
	log.Debug().
		Str("machine", machine.Name).
		Msg("Machine registration has expired. Sending a authurl to register")

	if registerRequest.Auth.AuthKey != "" {
		h.handleAuthKey(ctx, machineKey, registerRequest)

		return
	}

	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf("%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), machineKey.String())
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), machineKey.String())
	}

	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("reauth", "web", "error", machine.Namespace.Name).
			Inc()
		ctx.String(http.StatusInternalServerError, "")

		return
	}
	machineRegistrations.WithLabelValues("reauth", "web", "success", machine.Namespace.Name).
		Inc()
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
}

func (h *Headscale) handleMachineRefreshKey(
	ctx *gin.Context,
	machineKey key.MachinePublic,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	log.Debug().
		Str("machine", machine.Name).
		Msg("We have the OldNodeKey in the database. This is a key refresh")
	machine.NodeKey = NodePublicKeyStripPrefix(registerRequest.NodeKey)
	h.db.Save(&machine)

	resp.AuthURL = ""
	resp.User = *machine.Namespace.toUser()
	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot encode message")
		ctx.String(http.StatusInternalServerError, "Extremely sad!")

		return
	}
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
}

func (h *Headscale) handleMachineRegistrationNew(
	ctx *gin.Context,
	machineKey key.MachinePublic,
	registerRequest tailcfg.RegisterRequest,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is new, redirect the client to the registration URL
	log.Debug().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("The node is sending us a new NodeKey, sending auth url")
	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf(
			"%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			machineKey.String(),
		)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), MachinePublicKeyStripPrefix(machineKey))
	}

	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot encode message")
		ctx.String(http.StatusInternalServerError, "")

		return
	}
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
}

// TODO: check if any locks are needed around IP allocation.
func (h *Headscale) handleAuthKey(
	ctx *gin.Context,
	machineKey key.MachinePublic,
	registerRequest tailcfg.RegisterRequest,
) {
	machineKeyStr := MachinePublicKeyStripPrefix(machineKey)

	log.Debug().
		Str("func", "handleAuthKey").
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msgf("Processing auth key for %s", registerRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}

	pak, err := h.checkKeyValidity(registerRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "handleAuthKey").
			Str("machine", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false
		respBody, err := encode(resp, &machineKey, h.privateKey)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "handleAuthKey").
				Str("machine", registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("Cannot encode message")
			ctx.String(http.StatusInternalServerError, "")
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()

			return
		}

		ctx.Data(http.StatusUnauthorized, "application/json; charset=utf-8", respBody)
		log.Error().
			Caller().
			Str("func", "handleAuthKey").
			Str("machine", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey")
		machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()

		return
	}

	log.Debug().
		Str("func", "handleAuthKey").
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := NodePublicKeyStripPrefix(registerRequest.NodeKey)
	now := time.Now().UTC()

	machineToRegister := Machine{
		Name:           registerRequest.Hostinfo.Hostname,
		NamespaceID:    pak.Namespace.ID,
		MachineKey:     machineKeyStr,
		RegisterMethod: RegisterMethodAuthKey,
		Expiry:         &registerRequest.Expiry,
		NodeKey:        nodeKey,
		LastSeen:       &now,
		AuthKeyID:      uint(pak.ID),
	}

	machine, err := h.RegisterMachine(
		machineToRegister,
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("could not register machine")
		machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()
		ctx.String(
			http.StatusInternalServerError,
			"could not register machine",
		)

		return
	}

	h.UsePreAuthKey(pak)

	resp.MachineAuthorized = true
	resp.User = *pak.Namespace.toUser()
	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "handleAuthKey").
			Str("machine", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()
		ctx.String(http.StatusInternalServerError, "Extremely sad!")

		return
	}
	machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "success", pak.Namespace.Name).
		Inc()
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
	log.Info().
		Str("func", "handleAuthKey").
		Str("machine", registerRequest.Hostinfo.Hostname).
		Str("ips", strings.Join(machine.IPAddresses.ToStringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey")
}
