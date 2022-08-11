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

	"github.com/gorilla/mux"
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

	if err := h.pingDB(); err != nil {
		respond(err)

		return
	}

	respond(nil)
}

// KeyHandler provides the Headscale pub key
// Listens in /key.
func (h *Headscale) KeyHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write([]byte(MachinePublicKeyStripPrefix(h.privateKey.Public())))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

type registerWebAPITemplateConfig struct {
	Key string
}

var registerWebAPITemplate = template.Must(
	template.New("registerweb").Parse(`
<html>
	<head>
		<title>Registration - Headscale</title>
	</head>
	<body>
		<h1>headscale</h1>
		<h2>Machine registration</h2>
		<p>
			Run the command below in the headscale server to add this machine to your network:
		</p>
		<pre><code>headscale -n NAMESPACE nodes register --key {{.Key}}</code></pre>
	</body>
</html>
`))

// RegisterWebAPI shows a simple message in the browser to point to the CLI
// Listens in /register/:nkey.
//
// This is not part of the Tailscale control API, as we could send whatever URL
// in the RegisterResponse.AuthURL field.
func (h *Headscale) RegisterWebAPI(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	nodeKeyStr, ok := vars["nkey"]
	if !ok || nodeKeyStr == "" {
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

	var content bytes.Buffer
	if err := registerWebAPITemplate.Execute(&content, registerWebAPITemplateConfig{
		Key: nodeKeyStr,
	}); err != nil {
		log.Error().
			Str("func", "RegisterWebAPI").
			Err(err).
			Msg("Could not render register web API template")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err = writer.Write([]byte("Could not render register web API template"))
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
	_, err := writer.Write(content.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// RegistrationHandler handles the actual registration process of a machine
// Endpoint /machine/:mkey.
func (h *Headscale) RegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	machineKeyStr, ok := vars["mkey"]
	if !ok || machineKeyStr == "" {
		log.Error().
			Str("handler", "RegistrationHandler").
			Msg("No machine ID in request")
		http.Error(writer, "No machine ID in request", http.StatusBadRequest)

		return
	}

	body, _ := io.ReadAll(req.Body)

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse machine key")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Cannot parse machine key", http.StatusBadRequest)

		return
	}
	registerRequest := tailcfg.RegisterRequest{}
	err = decode(body, &registerRequest, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot decode message")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Cannot decode message", http.StatusBadRequest)

		return
	}

	now := time.Now().UTC()
	machine, err := h.GetMachineByMachineKey(machineKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		machineKeyStr := MachinePublicKeyStripPrefix(machineKey)

		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if registerRequest.Auth.AuthKey != "" {
			h.handleAuthKey(writer, req, machineKey, registerRequest)

			return
		}

		// Check if the node is waiting for interactive login
		//
		// TODO(juan): We could use this field to improve our protocol implementation,
		// and hold the request until the client closes it, or the interactive
		// login is completed (i.e., the user registers the machine).
		// This is not implemented yet, as it is no strictly required. The only side-effect
		// is that the client will hammer headscale with requests until it gets a
		// successful RegisterResponse.
		if registerRequest.Followup != "" {
			if _, ok := h.registrationCache.Get(NodePublicKeyStripPrefix(registerRequest.NodeKey)); ok {
				log.Debug().
					Caller().
					Str("machine", registerRequest.Hostinfo.Hostname).
					Str("NodeKey", registerRequest.NodeKey.ShortString()).
					Str("OldNodeKey", registerRequest.OldNodeKey.ShortString()).
					Str("Followup", registerRequest.Followup).
					Msg("Machine is waiting for interactive login")

				h.handleMachineRegistrationNew(writer, req, machineKey, registerRequest)

				return
			}
		}

		log.Info().
			Caller().
			Str("machine", registerRequest.Hostinfo.Hostname).
			Str("NodeKey", registerRequest.NodeKey.ShortString()).
			Str("OldNodeKey", registerRequest.OldNodeKey.ShortString()).
			Str("Followup", registerRequest.Followup).
			Msg("New machine not yet in the database")

		givenName, err := h.GenerateGivenName(registerRequest.Hostinfo.Hostname)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err)

			return
		}

		// The machine did not have a key to authenticate, which means
		// that we rely on a method that calls back some how (OpenID or CLI)
		// We create the machine and then keep it around until a callback
		// happens
		newMachine := Machine{
			MachineKey: machineKeyStr,
			Hostname:   registerRequest.Hostinfo.Hostname,
			GivenName:  givenName,
			NodeKey:    NodePublicKeyStripPrefix(registerRequest.NodeKey),
			LastSeen:   &now,
			Expiry:     &time.Time{},
		}

		if !registerRequest.Expiry.IsZero() {
			log.Trace().
				Caller().
				Str("machine", registerRequest.Hostinfo.Hostname).
				Time("expiry", registerRequest.Expiry).
				Msg("Non-zero expiry time requested")
			newMachine.Expiry = &registerRequest.Expiry
		}

		h.registrationCache.Set(
			newMachine.NodeKey,
			newMachine,
			registerCacheExpiration,
		)

		h.handleMachineRegistrationNew(writer, req, machineKey, registerRequest)

		return
	}

	// The machine is already registered, so we need to pass through reauth or key update.
	if machine != nil {
		// If the NodeKey stored in headscale is the same as the key presented in a registration
		// request, then we have a node that is either:
		// - Trying to log out (sending a expiry in the past)
		// - A valid, registered machine, looking for the node map
		// - Expired machine wanting to reauthenticate
		if machine.NodeKey == NodePublicKeyStripPrefix(registerRequest.NodeKey) {
			// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
			//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
			if !registerRequest.Expiry.IsZero() && registerRequest.Expiry.UTC().Before(now) {
				h.handleMachineLogOut(writer, req, machineKey, *machine)

				return
			}

			// If machine is not expired, and is register, we have a already accepted this machine,
			// let it proceed with a valid registration
			if !machine.isExpired() {
				h.handleMachineValidRegistration(writer, req, machineKey, *machine)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if machine.NodeKey == NodePublicKeyStripPrefix(registerRequest.OldNodeKey) &&
			!machine.isExpired() {
			h.handleMachineRefreshKey(writer, req, machineKey, registerRequest, *machine)

			return
		}

		// The machine has expired
		h.handleMachineExpired(writer, req, machineKey, registerRequest, *machine)

		return
	}
}

func (h *Headscale) getMapResponse(
	machineKey key.MachinePublic,
	mapRequest tailcfg.MapRequest,
	machine *Machine,
) ([]byte, error) {
	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", mapRequest.Hostinfo.Hostname).
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
		Debug: &tailcfg.Debug{
			DisableLogTail:      !h.cfg.LogTail.Enabled,
			RandomizeClientPort: h.cfg.RandomizeClientPort,
		},
	}

	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", mapRequest.Hostinfo.Hostname).
		// Interface("payload", resp).
		Msgf("Generated map response: %s", tailMapResponseToString(resp))

	var respBody []byte
	if mapRequest.Compress == "zstd" {
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
	writer http.ResponseWriter,
	req *http.Request,
	machineKey key.MachinePublic,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Str("machine", machine.Hostname).
		Msg("Client requested logout")

	err := h.ExpireMachine(&machine)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "handleMachineLogOut").
			Err(err).
			Msg("Failed to expire machine")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.User = *machine.Namespace.toUser()
	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

func (h *Headscale) handleMachineValidRegistration(
	writer http.ResponseWriter,
	req *http.Request,
	machineKey key.MachinePublic,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is valid, respond with redirect to /map
	log.Debug().
		Str("machine", machine.Hostname).
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
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("update", "web", "success", machine.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

func (h *Headscale) handleMachineExpired(
	writer http.ResponseWriter,
	req *http.Request,
	machineKey key.MachinePublic,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	// The client has registered before, but has expired
	log.Debug().
		Str("machine", machine.Hostname).
		Msg("Machine registration has expired. Sending a authurl to register")

	if registerRequest.Auth.AuthKey != "" {
		h.handleAuthKey(writer, req, machineKey, registerRequest)

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
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("reauth", "web", "success", machine.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

func (h *Headscale) handleMachineRefreshKey(
	writer http.ResponseWriter,
	req *http.Request,
	machineKey key.MachinePublic,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	log.Debug().
		Str("machine", machine.Hostname).
		Msg("We have the OldNodeKey in the database. This is a key refresh")
	machine.NodeKey = NodePublicKeyStripPrefix(registerRequest.NodeKey)

	if err := h.db.Save(&machine).Error; err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to update machine key in the database")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.User = *machine.Namespace.toUser()
	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

func (h *Headscale) handleMachineRegistrationNew(
	writer http.ResponseWriter,
	req *http.Request,
	machineKey key.MachinePublic,
	registerRequest tailcfg.RegisterRequest,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is new, redirect the client to the registration URL
	log.Debug().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("The node seems to be new, sending auth url")
	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf(
			"%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			machineKey.String(),
		)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), NodePublicKeyStripPrefix(registerRequest.NodeKey))
	}

	respBody, err := encode(resp, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// TODO: check if any locks are needed around IP allocation.
func (h *Headscale) handleAuthKey(
	writer http.ResponseWriter,
	req *http.Request,
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
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()

			return
		}

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusUnauthorized)
		_, err = writer.Write(respBody)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		log.Error().
			Caller().
			Str("func", "handleAuthKey").
			Str("machine", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey")

		if pak != nil {
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()
		} else {
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", "unknown").Inc()
		}

		return
	}

	log.Debug().
		Str("func", "handleAuthKey").
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := NodePublicKeyStripPrefix(registerRequest.NodeKey)

	// retrieve machine information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new machine and we will move
	// on to registration.
	machine, _ := h.GetMachineByMachineKey(machineKey)
	if machine != nil {
		log.Trace().
			Caller().
			Str("machine", machine.Hostname).
			Msg("machine already registered, refreshing with new auth key")

		machine.NodeKey = nodeKey
		machine.AuthKeyID = uint(pak.ID)
		err := h.RefreshMachine(machine, registerRequest.Expiry)
		if err != nil {
			log.Error().
				Caller().
				Str("machine", machine.Hostname).
				Err(err).
				Msg("Failed to refresh machine")

			return
		}
	} else {
		now := time.Now().UTC()

		givenName, err := h.GenerateGivenName(registerRequest.Hostinfo.Hostname)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err)

			return
		}

		machineToRegister := Machine{
			Hostname:       registerRequest.Hostinfo.Hostname,
			GivenName:      givenName,
			NamespaceID:    pak.Namespace.ID,
			MachineKey:     machineKeyStr,
			RegisterMethod: RegisterMethodAuthKey,
			Expiry:         &registerRequest.Expiry,
			NodeKey:        nodeKey,
			LastSeen:       &now,
			AuthKeyID:      uint(pak.ID),
		}

		machine, err = h.RegisterMachine(
			machineToRegister,
		)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("could not register machine")
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()
			http.Error(writer, "Internal server error", http.StatusInternalServerError)

			return
		}
	}

	err = h.UsePreAuthKey(pak)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to use pre-auth key")
		machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

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
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "success", pak.Namespace.Name).
		Inc()
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Str("func", "handleAuthKey").
		Str("machine", registerRequest.Hostinfo.Hostname).
		Str("ips", strings.Join(machine.IPAddresses.ToStringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey")
}
