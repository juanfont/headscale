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

	now := time.Now().UTC()
	machine, err := h.GetMachineByNodeKeys(req.NodeKey, req.OldNodeKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Info().Str("machine", req.Hostinfo.Hostname).Msg("New machine via Noise")

		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if req.Auth.AuthKey != "" {
			h.handleAuthKey(ctx, key.MachinePublic{}, req)

			return
		}
		hname, err := NormalizeToFQDNRules(
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
		Str("machine", machine.Name).
		Msg("Machine registration has expired. Sending a authurl to register")

	if registerRequest.Auth.AuthKey != "" {
		h.handleAuthKey(ctx, key.MachinePublic{}, registerRequest)

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
