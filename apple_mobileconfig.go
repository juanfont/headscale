package headscale

import (
	"bytes"
	"net/http"
	"text/template"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

// AppleMobileConfig shows a simple message in the browser to point to the CLI
// Listens in /register.
func (h *Headscale) AppleMobileConfig(ctx *gin.Context) {
	appleTemplate := template.Must(template.New("apple").Parse(`
<html>
	<body>
		<h1>Apple configuration profiles</h1>
		<p>
		    This page provides <a href="https://support.apple.com/guide/mdm/mdm-overview-mdmbf9e668/web">configuration profiles</a> for the official Tailscale clients for <a href="https://apps.apple.com/us/app/tailscale/id1470499037?ls=1">iOS</a> and <a href="https://apps.apple.com/ca/app/tailscale/id1475387142?mt=12">macOS</a>.
		</p>
		<p>
		    The profiles will configure Tailscale.app to use {{.Url}} as its control server.
		</p>

		<h3>Caution</h3>
		<p>You should always inspect the profile before installing it:</p>
		<!--
		<p><code>curl {{.Url}}/apple/ios</code></p>
		-->
		<p><code>curl {{.Url}}/apple/macos</code></p>
		
		<h2>Profiles</h2>

		<!--
		<h3>iOS</h3>
		<p>
		    <a href="/apple/ios" download="headscale_ios.mobileconfig">iOS profile</a>
		</p>
		-->
		
		<h3>macOS</h3>
		<p>Headscale can be set to the default server by installing a Headscale configuration profile:</p>
		<p>
		    <a href="/apple/macos" download="headscale_macos.mobileconfig">macOS profile</a>
		</p>

		<ol>
		<li>Download the profile, then open it. When it has been opened, there should be a notification that a profile can be installed</li>
		<li>Open System Preferences and go to "Profiles"</li>
		<li>Find and install the Headscale profile</li>
		<li>Restart Tailscale.app and log in</li>
		</ol>

		<p>Or</p>
		<p>Use your terminal to configure the default setting for Tailscale by issuing:</p>
		<code>defaults write io.tailscale.ipn.macos ControlURL {{.URL}}</code>

		<p>Restart Tailscale.app and log in.</p>
	
	</body>
</html>`))

	config := map[string]interface{}{
		"URL": h.cfg.ServerURL,
	}

	var payload bytes.Buffer
	if err := appleTemplate.Execute(&payload, config); err != nil {
		log.Error().
			Str("handler", "AppleMobileConfig").
			Err(err).
			Msg("Could not render Apple index template")
		ctx.Data(
			http.StatusInternalServerError,
			"text/html; charset=utf-8",
			[]byte("Could not render Apple index template"),
		)

		return
	}

	ctx.Data(http.StatusOK, "text/html; charset=utf-8", payload.Bytes())
}

func (h *Headscale) ApplePlatformConfig(ctx *gin.Context) {
	platform := ctx.Param("platform")

	id, err := uuid.NewV4()
	if err != nil {
		log.Error().
			Str("handler", "ApplePlatformConfig").
			Err(err).
			Msg("Failed not create UUID")
		ctx.Data(
			http.StatusInternalServerError,
			"text/html; charset=utf-8",
			[]byte("Failed to create UUID"),
		)

		return
	}

	contentID, err := uuid.NewV4()
	if err != nil {
		log.Error().
			Str("handler", "ApplePlatformConfig").
			Err(err).
			Msg("Failed not create UUID")
		ctx.Data(
			http.StatusInternalServerError,
			"text/html; charset=utf-8",
			[]byte("Failed to create UUID"),
		)

		return
	}

	platformConfig := AppleMobilePlatformConfig{
		UUID: contentID,
		URL:  h.cfg.ServerURL,
	}

	var payload bytes.Buffer

	switch platform {
	case "macos":
		if err := macosTemplate.Execute(&payload, platformConfig); err != nil {
			log.Error().
				Str("handler", "ApplePlatformConfig").
				Err(err).
				Msg("Could not render Apple macOS template")
			ctx.Data(
				http.StatusInternalServerError,
				"text/html; charset=utf-8",
				[]byte("Could not render Apple macOS template"),
			)

			return
		}
	case "ios":
		if err := iosTemplate.Execute(&payload, platformConfig); err != nil {
			log.Error().
				Str("handler", "ApplePlatformConfig").
				Err(err).
				Msg("Could not render Apple iOS template")
			ctx.Data(
				http.StatusInternalServerError,
				"text/html; charset=utf-8",
				[]byte("Could not render Apple iOS template"),
			)

			return
		}
	default:
		ctx.Data(
			http.StatusOK,
			"text/html; charset=utf-8",
			[]byte("Invalid platform, only ios and macos is supported"),
		)

		return
	}

	config := AppleMobileConfig{
		UUID:    id,
		URL:     h.cfg.ServerURL,
		Payload: payload.String(),
	}

	var content bytes.Buffer
	if err := commonTemplate.Execute(&content, config); err != nil {
		log.Error().
			Str("handler", "ApplePlatformConfig").
			Err(err).
			Msg("Could not render Apple platform template")
		ctx.Data(
			http.StatusInternalServerError,
			"text/html; charset=utf-8",
			[]byte("Could not render Apple platform template"),
		)

		return
	}

	ctx.Data(
		http.StatusOK,
		"application/x-apple-aspen-config; charset=utf-8",
		content.Bytes(),
	)
}

type AppleMobileConfig struct {
	UUID    uuid.UUID
	URL     string
	Payload string
}

type AppleMobilePlatformConfig struct {
	UUID uuid.UUID
	URL  string
}

var commonTemplate = template.Must(
	template.New("mobileconfig").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>PayloadUUID</key>
    <string>{{.UUID}}</string>
    <key>PayloadDisplayName</key>
    <string>Headscale</string>
    <key>PayloadDescription</key>
    <string>Configure Tailscale login server to: {{.URL}}</string>
    <key>PayloadIdentifier</key>
    <string>com.github.juanfont.headscale</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
    {{.Payload}}
    </array>
  </dict>
</plist>`),
)

var iosTemplate = template.Must(template.New("iosTemplate").Parse(`
    <dict>
        <key>PayloadType</key>
        <string>io.tailscale.ipn.ios</string>
        <key>PayloadUUID</key>
        <string>{{.UUID}}</string>
        <key>PayloadIdentifier</key>
        <string>com.github.juanfont.headscale</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadEnabled</key>
        <true/>

        <key>ControlURL</key>
        <string>{{.URL}}</string>
    </dict>
`))

var macosTemplate = template.Must(template.New("macosTemplate").Parse(`
    <dict>
        <key>PayloadType</key>
        <string>io.tailscale.ipn.macos</string>
        <key>PayloadUUID</key>
        <string>{{.UUID}}</string>
        <key>PayloadIdentifier</key>
        <string>com.github.juanfont.headscale</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadEnabled</key>
        <true/>

        <key>ControlURL</key>
        <string>{{.URL}}</string>
    </dict>
`))
