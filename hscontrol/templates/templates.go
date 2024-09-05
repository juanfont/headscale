package templates

import (
	"bytes"
	"embed"
	_ "embed"
	"html/template"
	"os"
	"path/filepath"
)

const (
	OidcCallbackTemplate      = "oidc_callback.html"
	ConfigHelpAppleTemplate   = "config_help_apple.html"
	ConfigHelpWindowsTemplate = "config_help_windows.html"
	RegisterNodeTemplate      = "register_node.html"
)

type Template struct {
	// template file name
	Name string
	// template variables
	Vars map[string]interface{}
	// path to a directory of user-defined templates
	UserTemplateDirPath string
	// Embed fs with the standard templates
	EmbedFS embed.FS
}

// Render render html page content from template
func (t Template) Render() ([]byte, error) {
	// Load default template
	tmplFile, err := t.EmbedFS.ReadFile("html/" + t.Name)
	if err != nil {
		return nil, err
	}

	// If a user template file exists, load a template from a user file
	// else use the standard embedded template
	if t.UserTemplateDirPath != "" {
		UserTmplFilePath := filepath.Join(t.UserTemplateDirPath, t.Name)
		if _, err := os.Stat(UserTmplFilePath); !os.IsNotExist(err) {
			tmplFile, err = os.ReadFile(UserTmplFilePath)
			if err != nil {
				return nil, err
			}
		}
	}

	var tmpl bytes.Buffer
	err = template.Must(template.New(t.Name).Parse(string(tmplFile))).Execute(&tmpl, t.Vars)
	if err != nil {
		return nil, err
	}

	return tmpl.Bytes(), err
}
