package headscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (h *Headscale) NoiseRegistrationHandler(ctx *gin.Context) {
	log.Trace().Caller().Msgf("Noise registration handler for client %s", ctx.ClientIP())
	body, _ := io.ReadAll(ctx.Request.Body)
	req := tailcfg.RegisterRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse RegisterRequest")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		ctx.String(http.StatusInternalServerError, "Eek!")

		return
	}

	log.Info().Caller().
		Str("nodekey", req.NodeKey.ShortString()).
		Str("oldnodekey", req.OldNodeKey.ShortString()).Msg("Nodekys!")

	now := time.Now().UTC()
	machine, err := h.GetMachineByNodeKeys(req.NodeKey, req.OldNodeKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Info().Str("machine", req.Hostinfo.Hostname).Msg("New machine via Noise")

		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if req.Auth.AuthKey != "" {
			h.handleNoiseAuthKey(ctx, req)

			return
		}
		hname, err := NormalizeToFQDNRules(
			req.Hostinfo.Hostname,
			h.cfg.OIDC.StripEmaildomain,
		)
		if err != nil {
			log.Error().
				Caller().
				Str("hostinfo.name", req.Hostinfo.Hostname).
				Err(err)

			return
		}

		// The machine did not have a key to authenticate, which means
		// that we rely on a method that calls back some how (OpenID or CLI)
		// We create the machine and then keep it around until a callback
		// happens
		newMachine := Machine{
			MachineKey: "",
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
			NodePublicKeyStripPrefix(req.NodeKey),
			newMachine,
			registerCacheExpiration,
		)

		h.handleMachineRegistrationNew(ctx, key.MachinePublic{}, req)

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
				h.handleNoiseNodeLogOut(ctx, *machine)

				return
			}

			// If machine is not expired, and is register, we have a already accepted this machine,
			// let it proceed with a valid registration
			if !machine.isExpired() {
				h.handleNoiseNodeValidRegistration(ctx, *machine)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if machine.NodeKey == NodePublicKeyStripPrefix(req.OldNodeKey) &&
			!machine.isExpired() {
			h.handleNoiseNodeRefreshKey(ctx, req, *machine)

			return
		}

		// The node has expired
		h.handleNoiseNodeExpired(ctx, req, *machine)

		return
	}
}

// NoisePollNetMapHandler takes care of /machine/:id/map
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (h *Headscale) NoisePollNetMapHandler(ctx *gin.Context) {
	log.Trace().
		Caller().
		Str("id", ctx.Param("id")).
		Msg("PollNetMapHandler called")
	body, _ := io.ReadAll(ctx.Request.Body)

	req := tailcfg.MapRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse MapRequest")
		ctx.String(http.StatusInternalServerError, "Eek!")

		return
	}

	machine, err := h.GetMachineByNodeKeys(req.NodeKey, key.NodePublic{})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Warn().Caller().
				Msgf("Ignoring request, cannot find node with node key %s", req.NodeKey.String())
			ctx.String(http.StatusUnauthorized, "")

			return
		}
		log.Error().
			Caller().
			Msgf("Failed to fetch machine from the database with NodeKey: %s", req.NodeKey.String())
		ctx.String(http.StatusInternalServerError, "")

		return
	}
	log.Trace().Caller().
		Str("NodeKey", req.NodeKey.ShortString()).
		Str("machine", machine.Name).
		Msg("Found machine in database")

	hname, err := NormalizeToFQDNRules(
		req.Hostinfo.Hostname,
		h.cfg.OIDC.StripEmaildomain,
	)
	if err != nil {
		log.Error().
			Caller().
			Str("hostinfo.name", req.Hostinfo.Hostname).
			Err(err)
	}
	machine.Name = hname
	machine.HostInfo = HostInfo(*req.Hostinfo)
	machine.DiscoKey = DiscoPublicKeyStripPrefix(req.DiscoKey)
	now := time.Now().UTC()

	// update ACLRules with peer informations (to update server tags if necessary)
	if h.aclPolicy != nil {
		err = h.UpdateACLRules()
		if err != nil {
			log.Error().
				Caller().
				Str("func", "handleAuthKey").
				Str("machine", machine.Name).
				Err(err)
		}
	}
	// From Tailscale client:
	//
	// ReadOnly is whether the client just wants to fetch the MapResponse,
	// without updating their Endpoints. The Endpoints field will be ignored and
	// LastSeen will not be updated and peers will not be notified of changes.
	//
	// The intended use is for clients to discover the DERP map at start-up
	// before their first real endpoint update.
	if !req.ReadOnly {
		machine.Endpoints = req.Endpoints
		machine.LastSeen = &now
	}
	h.db.Updates(machine)

	data, err := h.getMapResponse(key.MachinePublic{}, req, machine)
	if err != nil {
		log.Error().
			Caller().
			Str("id", ctx.Param("id")).
			Str("machine", machine.Name).
			Err(err).
			Msg("Failed to get Map response")
		ctx.String(http.StatusInternalServerError, ":(")

		return
	}

	// We update our peers if the client is not sending ReadOnly in the MapRequest
	// so we don't distribute its initial request (it comes with
	// empty endpoints to peers)

	// Details on the protocol can be found in https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L696
	log.Debug().
		Caller().
		Str("id", ctx.Param("id")).
		Str("machine", machine.Name).
		Bool("readOnly", req.ReadOnly).
		Bool("omitPeers", req.OmitPeers).
		Bool("stream", req.Stream).
		Msg("Noise client map request processed")

	if req.ReadOnly {
		log.Info().
			Caller().
			Str("machine", machine.Name).
			Msg("Noise client is starting up. Probably interested in a DERP map")
			// log.Info().Str("machine", machine.Name).Bytes("resp", data).Msg("Sending DERP map to client")

		ctx.Data(http.StatusOK, "application/json; charset=utf-8", data)

		return
	}

	// There has been an update to _any_ of the nodes that the other nodes would
	// need to know about
	log.Trace().Msgf("Updating peers for noise machine %s", machine.Name)
	h.setLastStateChangeToNow(machine.Namespace.Name)

	// The request is not ReadOnly, so we need to set up channels for updating
	// peers via longpoll

	// Only create update channel if it has not been created
	log.Trace().
		Caller().
		Str("id", ctx.Param("id")).
		Str("machine", machine.Name).
		Msg("Noise loading or creating update channel")

	// TODO: could probably remove all that duplication once generics land.
	closeChanWithLog := func(channel interface{}, name string) {
		log.Trace().
			Caller().
			Str("machine", machine.Name).
			Str("channel", "Done").
			Msg(fmt.Sprintf("Closing %s channel", name))

		switch c := channel.(type) {
		case (chan struct{}):
			close(c)

		case (chan []byte):
			close(c)
		}
	}

	const chanSize = 8
	updateChan := make(chan struct{}, chanSize)
	defer closeChanWithLog(updateChan, "updateChan")

	pollDataChan := make(chan []byte, chanSize)
	defer closeChanWithLog(pollDataChan, "pollDataChan")

	keepAliveChan := make(chan []byte)
	defer closeChanWithLog(keepAliveChan, "keepAliveChan")

	if req.OmitPeers && !req.Stream {
		log.Info().
			Caller().
			Str("machine", machine.Name).
			Msg("Noise client sent endpoint update and is ok with a response without peer list")
		ctx.Data(http.StatusOK, "application/json; charset=utf-8", data)

		// It sounds like we should update the nodes when we have received a endpoint update
		// even tho the comments in the tailscale code dont explicitly say so.
		updateRequestsFromNode.WithLabelValues(machine.Namespace.Name, machine.Name, "endpoint-update").
			Inc()
		updateChan <- struct{}{}

		return
	} else if req.OmitPeers && req.Stream {
		log.Warn().
			Caller().
			Str("machine", machine.Name).
			Msg("Ignoring request, don't know how to handle it")
		ctx.String(http.StatusBadRequest, "")

		return
	}

	log.Info().
		Caller().
		Str("machine", machine.Name).
		Msg("Noise client is ready to access the tailnet")
	log.Info().
		Caller().
		Str("machine", machine.Name).
		Msg("Sending initial map")
	pollDataChan <- data

	log.Info().
		Caller().
		Str("machine", machine.Name).
		Msg("Notifying peers")
	updateRequestsFromNode.WithLabelValues(machine.Namespace.Name, machine.Name, "full-update").
		Inc()
	updateChan <- struct{}{}

	h.PollNetMapStream(
		ctx,
		machine,
		req,
		key.MachinePublic{},
		pollDataChan,
		keepAliveChan,
		updateChan,
	)
	log.Trace().
		Caller().
		Str("id", ctx.Param("id")).
		Str("machine", machine.Name).
		Msg("Finished stream, closing PollNetMap session")
}

func (h *Headscale) handleNoiseNodeValidRegistration(
	ctx *gin.Context,
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

	machineRegistrations.WithLabelValues("update", "web", "success", machine.Namespace.Name).
		Inc()
	ctx.JSON(http.StatusOK, resp)
}

func (h *Headscale) handleNoiseNodeLogOut(
	ctx *gin.Context,
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
	ctx.JSON(http.StatusOK, resp)
}

func (h *Headscale) handleNoiseNodeRefreshKey(
	ctx *gin.Context,
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
	ctx.JSON(http.StatusOK, resp)
}

func (h *Headscale) handleNoiseNodeExpired(
	ctx *gin.Context,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	// The client has registered before, but has expired
	log.Debug().
		Caller().
		Str("machine", machine.Name).
		Msg("Machine registration has expired. Sending a authurl to register")

	if registerRequest.Auth.AuthKey != "" {
		h.handleNoiseAuthKey(ctx, registerRequest)

		return
	}

	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf("%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), machine.NodeKey)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), machine.NodeKey)
	}

	machineRegistrations.WithLabelValues("reauth", "web", "success", machine.Namespace.Name).
		Inc()
	ctx.JSON(http.StatusOK, resp)
}

func (h *Headscale) handleNoiseAuthKey(
	ctx *gin.Context,
	registerRequest tailcfg.RegisterRequest,
) {
	log.Debug().
		Caller().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msgf("Processing auth key for %s over Noise", registerRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}

	pak, err := h.checkKeyValidity(registerRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Caller().
			Str("machine", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false

		ctx.JSON(http.StatusUnauthorized, resp)
		log.Error().
			Caller().
			Str("machine", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey over Noise")

		if pak != nil {
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()
		} else {
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", "unknown").Inc()
		}

		return
	}

	log.Debug().
		Caller().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := NodePublicKeyStripPrefix(registerRequest.NodeKey)

	// retrieve machine information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new machine and we will move
	// on to registration.
	machine, _ := h.GetMachineByNodeKeys(registerRequest.NodeKey, registerRequest.OldNodeKey)
	if machine != nil {
		log.Trace().
			Caller().
			Str("machine", machine.Name).
			Msg("machine already registered, refreshing with new auth key")

		machine.NodeKey = nodeKey
		machine.AuthKeyID = uint(pak.ID)
		h.RefreshMachine(machine, registerRequest.Expiry)
	} else {
		now := time.Now().UTC()
		machineToRegister := Machine{
			Name:           registerRequest.Hostinfo.Hostname,
			NamespaceID:    pak.Namespace.ID,
			MachineKey:     "",
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
			ctx.String(
				http.StatusInternalServerError,
				"could not register machine",
			)

			return
		}
	}

	h.UsePreAuthKey(pak)

	resp.MachineAuthorized = true
	resp.User = *pak.Namespace.toUser()

	machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "success", pak.Namespace.Name).
		Inc()
	ctx.JSON(http.StatusOK, resp)
	log.Info().
		Caller().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Str("ips", strings.Join(machine.IPAddresses.ToStringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey on Noise")
}
