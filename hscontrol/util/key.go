package util

import (
	"encoding/json"
	"errors"
	"regexp"

	"tailscale.com/types/key"
)

var (
	NodePublicKeyRegex       = regexp.MustCompile("nodekey:[a-fA-F0-9]+")
	ErrCannotDecryptResponse = errors.New("cannot decrypt response")
	ZstdCompression          = "zstd"
)

func DecodeAndUnmarshalNaCl(
	msg []byte,
	output interface{},
	pubKey *key.MachinePublic,
	privKey *key.MachinePrivate,
) error {
	decrypted, ok := privKey.OpenFrom(*pubKey, msg)
	if !ok {
		return ErrCannotDecryptResponse
	}

	if err := json.Unmarshal(decrypted, output); err != nil {
		return err
	}

	return nil
}
