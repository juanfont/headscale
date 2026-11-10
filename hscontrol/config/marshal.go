package config

import (
	"github.com/juanfont/headscale/hscontrol/types"
)

// Marshal renders cfg in the file format of ext: ".yaml", ".yml", ".json"
// or ".hujson", keyed as a file is, with secrets redacted: a secret shows
// only a file: reference, a URL no userinfo, a DNS provider only its name
// and file: references.
func Marshal(cfg *types.Config, ext string) ([]byte, error) {
	parser, err := configParser(ext)
	if err != nil {
		return nil, err
	}

	return parser.Marshal(plainMap(cfg, true))
}
