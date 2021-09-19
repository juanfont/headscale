package headscale

import (
	"bytes"
	"net/http"
	"text/template"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
)

// AppleMobileConfig shows a simple message in the browser to point to the CLI
// Listens in /register
func (h *Headscale) AppleMobileConfig(c *gin.Context) {
	t := template.Must(template.New("apple").Parse(`
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
		<p><code>curl {{.Url}}/apple/ios</code></p>
		<p><code>curl {{.Url}}/apple/macos</code></p>
		
		<h3>Profiles</h3>
		<p>
		    <a href="/apple/ios" download="headscale_ios.mobileconfig">iOS</a>
		</p>
		
		<p>
		    <a href="/apple/macos" download="headscale_macos.mobileconfig">macOS</a>
		</p>
	
	</body>
</html>`))

	config := map[string]interface{}{
		"Url": h.cfg.ServerURL,
	}

	var payload bytes.Buffer
	if err := t.Execute(&payload, config); err != nil {
		c.Error(err)
		return
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", payload.Bytes())
}

func (h *Headscale) ApplePlatformConfig(c *gin.Context) {
	platform := c.Param("platform")

	id, err := uuid.NewV4()
	if err != nil {
		c.Error(err)
		return
	}

	contentId, err := uuid.NewV4()
	if err != nil {
		c.Error(err)
		return
	}

	platformConfig := AppleMobilePlatformConfig{
		UUID: contentId,
		Url:  h.cfg.ServerURL,
	}

	var payload bytes.Buffer

	switch platform {
	case "macos":
		if err := macosTemplate.Execute(&payload, platformConfig); err != nil {
			c.Error(err)
			return
		}
	case "ios":
		if err := iosTemplate.Execute(&payload, platformConfig); err != nil {
			c.Error(err)
			return
		}
	default:
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("Invalid platform, only ios and macos is supported"))
		return
	}

	config := AppleMobileConfig{
		UUID:    id,
		Url:     h.cfg.ServerURL,
		Payload: payload.String(),
	}

	var content bytes.Buffer
	if err := commonTemplate.Execute(&content, config); err != nil {
		c.Error(err)
		return
	}

	c.Data(http.StatusOK, "application/x-apple-aspen-config; charset=utf-8", content.Bytes())
}

type AppleMobileConfig struct {
	UUID    uuid.UUID
	Url     string
	Payload string
}

type AppleMobilePlatformConfig struct {
	UUID uuid.UUID
	Url  string
}

var commonTemplate = template.Must(template.New("mobileconfig").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>PayloadUUID</key>
    <string>{{.UUID}}</string>
    <key>PayloadDisplayName</key>
    <string>Headscale</string>
    <key>PayloadDescription</key>
    <string>Configure Tailscale login server to: {{.Url}}</string>
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
</plist>`))

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
        <string>{{.Url}}</string>
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
        <string>{{.Url}}</string>
    </dict>
`))
