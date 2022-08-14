package headscale

import (
	"encoding/binary"
	"encoding/json"

	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
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
		return h.marshalResponse(mapResponse, mapRequest.Compress, key.MachinePublic{})
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

	return h.marshalResponse(mapResponse, mapRequest.Compress, machineKey)
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
		return h.marshalResponse(keepAliveResponse, mapRequest.Compress, key.MachinePublic{})
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

	return h.marshalResponse(keepAliveResponse, mapRequest.Compress, machineKey)
}

func (h *Headscale) marshalResponse(
	resp interface{},
	compression string,
	machineKey key.MachinePublic,
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
		encoder, _ := zstd.NewWriter(nil)
		respBody = encoder.EncodeAll(jsonBody, nil)
		if !machineKey.IsZero() { // if legacy protocol
			respBody = h.privateKey.SealTo(machineKey, respBody)
		}
	} else {
		if !machineKey.IsZero() { // if legacy protocol
			respBody = h.privateKey.SealTo(machineKey, jsonBody)
		}
	}

	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}
