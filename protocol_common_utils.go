package headscale

import (
	"encoding/binary"
	"encoding/json"

	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (h *Headscale) getMapKeepAliveResponse(
	machineKey key.MachinePublic,
	mapRequest tailcfg.MapRequest,
) ([]byte, error) {
	mapResponse := tailcfg.MapResponse{
		KeepAlive: true,
	}
	var respBody []byte
	var err error
	if mapRequest.Compress == ZstdCompression {
		src, err := json.Marshal(mapResponse)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "getMapKeepAliveResponse").
				Err(err).
				Msg("Failed to marshal keepalive response for the client")

			return nil, err
		}
		encoder, _ := zstd.NewWriter(nil)
		srcCompressed := encoder.EncodeAll(src, nil)
		respBody = h.privateKey.SealTo(machineKey, srcCompressed)
	} else {
		respBody, err = encode(mapResponse, &machineKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	}
	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}
