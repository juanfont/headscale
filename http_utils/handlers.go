package http_utils

import (
	"bytes"
	"net/http"
	"github.com/rs/zerolog/log"
)

var Handler404 = http.HandlerFunc(Do404)

func Do404(
	writer http.ResponseWriter,
	req *http.Request,
) {
	var content bytes.Buffer
	content.Write([]byte {0x34, 0x30, 0x34}) //"404" in ascii hex.
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusNotFound)
	_, err := writer.Write(content.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}