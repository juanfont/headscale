package hscontrol

import (
	"encoding/binary"
	"encoding/json"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (h *Headscale) getMapResponseData(
	mapRequest tailcfg.MapRequest,
	machine *Machine,
	isNoise bool,
) ([]byte, error) {
	mapResponse, err := h.generateMapResponse(mapRequest, machine)
	if err != nil {
		return nil, err
	}

	if isNoise {
		return h.marshalMapResponse(mapResponse, key.MachinePublic{}, mapRequest.Compress, isNoise)
	}

	var machineKey key.MachinePublic
	err = machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machine.MachineKey)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse client key")

		return nil, err
	}

	return h.marshalMapResponse(mapResponse, machineKey, mapRequest.Compress, isNoise)
}

func (h *Headscale) getMapKeepAliveResponseData(
	mapRequest tailcfg.MapRequest,
	machine *Machine,
	isNoise bool,
) ([]byte, error) {
	keepAliveResponse := tailcfg.MapResponse{
		KeepAlive: true,
	}

	if isNoise {
		return h.marshalMapResponse(keepAliveResponse, key.MachinePublic{}, mapRequest.Compress, isNoise)
	}

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machine.MachineKey)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse client key")

		return nil, err
	}

	return h.marshalMapResponse(keepAliveResponse, machineKey, mapRequest.Compress, isNoise)
}

func (h *Headscale) marshalResponse(
	resp interface{},
	machineKey key.MachinePublic,
	isNoise bool,
) ([]byte, error) {
	jsonBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot marshal response")

		return nil, err
	}

	if isNoise {
		return jsonBody, nil
	}

	return h.privateKey.SealTo(machineKey, jsonBody), nil
}

func (h *Headscale) marshalMapResponse(
	resp interface{},
	machineKey key.MachinePublic,
	compression string,
	isNoise bool,
) ([]byte, error) {
	jsonBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot marshal map response")
	}

	var respBody []byte
	if compression == ZstdCompression {
		respBody = zstdEncode(jsonBody)
		if !isNoise { // if legacy protocol
			respBody = h.privateKey.SealTo(machineKey, respBody)
		}
	} else {
		if !isNoise { // if legacy protocol
			respBody = h.privateKey.SealTo(machineKey, jsonBody)
		} else {
			respBody = jsonBody
		}
	}

	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func zstdEncode(in []byte) []byte {
	encoder, ok := zstdEncoderPool.Get().(*zstd.Encoder)
	if !ok {
		panic("invalid type in sync pool")
	}
	out := encoder.EncodeAll(in, nil)
	_ = encoder.Close()
	zstdEncoderPool.Put(encoder)

	return out
}

var zstdEncoderPool = &sync.Pool{
	New: func() any {
		encoder, err := smallzstd.NewEncoder(
			nil,
			zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			panic(err)
		}

		return encoder
	},
}
