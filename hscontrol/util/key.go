package util

import (
	"errors"
)

var (
	ErrCannotDecryptResponse = errors.New("decrypting response")
	ZstdCompression          = "zstd"
)
