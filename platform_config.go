package headscale

import (
	"bytes"
	"html/template"
	"net/http"
	textTemplate "text/template"

	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// WindowsConfigMessage shows a simple message in the browser for how to configure the Windows Tailscale client.
func (h *Headscale) WindowsConfigMessage(
	writer http.ResponseWriter,
	req *http.Request,
) {
	winTemplate := template.Must(template.New("windows").Parse(`
<html>
	<body>
		<h1>headscale</h1>
		<h2>Windows registry configuration</h2>
		<p>
		    This page provides Windows registry information for the official Windows Tailscale client.
		<p>
		<p>
		    The registry file will configure Tailscale to use <code>{{.URL}}</code> as its control server.
		<p>
		<h3>Caution</h3>
		<p>You should always download and inspect the registry file before installing it:</p>
		<pre><code>curl {{.URL}}/windows/tailscale.reg</code></pre>

		<h2>Installation</h2>
		<p>Headscale can be set to the default server by running the registry file:</p>

		<p>
		    <a href="/windows/tailscale.reg" download="tailscale.reg">Windows registry file</a>
		</p>

		<ol>
			<li>Download the registry file, then run it</li>
			<li>Follow the prompts</li>
			<li>Install and run the official windows Tailscale client</li>
			<li>When the installation has finished, start Tailscale, and log in by clicking the icon in the system tray</li>
		</ol>
		<p>Or</p>
		<p>Open command prompt with Administrator rights. Issue the following commands to add the required registry entries:</p>
		<pre>
<code>REG ADD "HKLM\Software\Tailscale IPN" /v UnattendedMode /t REG_SZ /d always
REG ADD "HKLM\Software\Tailscale IPN" /v LoginURL /t REG_SZ /d "{{.URL}}"</code></pre>
		<p>
		    Restart Tailscale and log in.
		<p>
	</body>
</html>
`))

	config := map[string]interface{}{
		"URL": h.cfg.ServerURL,
	}

	var payload bytes.Buffer
	if err := winTemplate.Execute(&payload, config); err != nil {
		log.Error().
			Str("handler", "WindowsRegConfig").
			Err(err).
			Msg("Could not render Windows index template")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Windows index template"))
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
	_, err := writer.Write(payload.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// WindowsRegConfig generates and serves a .reg file configured with the Headscale server address.
func (h *Headscale) WindowsRegConfig(
	writer http.ResponseWriter,
	req *http.Request,
) {
	config := WindowsRegistryConfig{
		URL: h.cfg.ServerURL,
	}

	var content bytes.Buffer
	if err := windowsRegTemplate.Execute(&content, config); err != nil {
		log.Error().
			Str("handler", "WindowsRegConfig").
			Err(err).
			Msg("Could not render Apple macOS template")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Windows registry template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	writer.Header().Set("Content-Type", "text/x-ms-regedit; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write(content.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// AppleConfigMessage shows a simple message in the browser to point the user to the iOS/MacOS profile and instructions for how to install it.
func (h *Headscale) AppleConfigMessage(
	writer http.ResponseWriter,
	req *http.Request,
) {
	appleTemplate := template.Must(template.New("apple").Parse(`
<html>
	<body>
		<h1>headscale</h1>
		<h2>Apple configuration profiles</h2>
		<p>
		    This page provides <a href="https://support.apple.com/guide/mdm/mdm-overview-mdmbf9e668/web">configuration profiles</a> for the official Tailscale clients for <a href="https://apps.apple.com/us/app/tailscale/id1470499037?ls=1">iOS</a> and <a href="https://apps.apple.com/ca/app/tailscale/id1475387142?mt=12">macOS</a>.
		</p>
		<p>
		    The profiles will configure Tailscale.app to use <code>{{.URL}}</code> as its control server.
		</p>

		<h3>Caution</h3>
		<p>You should always download and inspect the profile before installing it:</p>
		<!--
		<pre><code>curl {{.URL}}/apple/ios</code></pre>
		-->
		<pre><code>curl {{.URL}}/apple/macos</code></pre>

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

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Apple index template"))
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
	_, err := writer.Write(payload.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

func (h *Headscale) ApplePlatformConfig(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	platform, ok := vars["platform"]
	if !ok {
		log.Error().
			Str("handler", "ApplePlatformConfig").
			Msg("No platform specified")
		http.Error(writer, "No platform specified", http.StatusBadRequest)

		return
	}

	id, err := uuid.NewV4()
	if err != nil {
		log.Error().
			Str("handler", "ApplePlatformConfig").
			Err(err).
			Msg("Failed not create UUID")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Failed to create UUID"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	contentID, err := uuid.NewV4()
	if err != nil {
		log.Error().
			Str("handler", "ApplePlatformConfig").
			Err(err).
			Msg("Failed not create UUID")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Failed to create content UUID"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

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

			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusInternalServerError)
			_, err := writer.Write([]byte("Could not render Apple macOS template"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}
	case "ios":
		if err := iosTemplate.Execute(&payload, platformConfig); err != nil {
			log.Error().
				Str("handler", "ApplePlatformConfig").
				Err(err).
				Msg("Could not render Apple iOS template")

			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusInternalServerError)
			_, err := writer.Write([]byte("Could not render Apple iOS template"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}
	default:
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Invalid platform, only ios and macos is supported"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

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

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Apple platform template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	writer.Header().Set("Content-Type", "application/x-apple-aspen-config; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(content.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

type WindowsRegistryConfig struct {
	URL string
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

var windowsRegTemplate = textTemplate.Must(
	textTemplate.New("windowsconfig").Parse(`Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Tailscale IPN]
"UnattendedMode"="always"
"LoginURL"="{{.URL}}"
`))

var commonTemplate = textTemplate.Must(
	textTemplate.New("mobileconfig").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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

var iosTemplate = textTemplate.Must(textTemplate.New("iosTemplate").Parse(`
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
