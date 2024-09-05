package hscontrol

import (
	"bytes"
	_ "embed"
	"github.com/gofrs/uuid/v5"
	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"html/template"
	"net/http"
	textTemplate "text/template"
)

// PlatformConfigHelp shows a simple page in the browser for how to configure the Apple/Windows Tailscale client.
func (h *Headscale) PlatformConfigHelp(
	writer http.ResponseWriter,
	req *http.Request,
) {
	tmplVars := map[string]interface{}{
		"URL": h.cfg.ServerURL,
	}

	switch req.URL.Path {
	case "/apple":
		renderPlatformConfigHelpTemplate(h, templates.ConfigHelpAppleTemplate, tmplVars, writer)
		return
	case "/windows":
		renderPlatformConfigHelpTemplate(h, templates.ConfigHelpWindowsTemplate, tmplVars, writer)
		return
	default:
		return
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
	handleMacError := func(ierr error) {
		log.Error().
			Str("handler", "ApplePlatformConfig").
			Err(ierr).
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
	}

	switch platform {
	case "macos-standalone":
		if err := macosStandaloneTemplate.Execute(&payload, platformConfig); err != nil {
			handleMacError(err)

			return
		}
	case "macos-app-store":
		if err := macosAppStoreTemplate.Execute(&payload, platformConfig); err != nil {
			handleMacError(err)

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
		_, err := writer.Write(
			[]byte("Invalid platform. Only ios, macos-app-store and macos-standalone are supported"),
		)
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

	writer.Header().
		Set("Content-Type", "application/x-apple-aspen-config; charset=utf-8")
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

var macosAppStoreTemplate = template.Must(template.New("macosTemplate").Parse(`
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

var macosStandaloneTemplate = template.Must(template.New("macosStandaloneTemplate").Parse(`
   <dict>
       <key>PayloadType</key>
       <string>io.tailscale.ipn.macsys</string>
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

// renderPlatformConfigHelpTemplate render page content from the template
func renderPlatformConfigHelpTemplate(
	h *Headscale,
	tmplName string,
	vars map[string]interface{},
	writer http.ResponseWriter,
) {
	tmpl, err := templates.Template{
		Name:                tmplName,
		Vars:                vars,
		UserTemplateDirPath: h.cfg.UserTemplateDirPath,
		EmbedFS:             htmlTemplatesEmbedFS,
	}.Render()

	if err != nil {
		util.LogErr(err, "Could not render template: "+tmplName)

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render template: " + tmplName))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(tmpl)
	if err != nil {
		util.LogErr(err, "Failed to write response")
	}
}
