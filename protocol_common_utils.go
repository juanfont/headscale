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
		return h.marshalMapResponse(mapResponse, key.MachinePublic{}, mapRequest.Compress)
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

	return h.marshalMapResponse(mapResponse, machineKey, mapRequest.Compress)
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
		return h.marshalMapResponse(keepAliveResponse, key.MachinePublic{}, mapRequest.Compress)
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

	return h.marshalMapResponse(keepAliveResponse, machineKey, mapRequest.Compress)
}

func (h *Headscale) marshalResponse(
	resp interface{},
	machineKey key.MachinePublic,
) ([]byte, error) {
	jsonBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot marshal response")

		return nil, err
	}

	if machineKey.IsZero() { // if Noise
		return jsonBody, nil
	}

	return h.privateKey.SealTo(machineKey, jsonBody), nil
}

func (h *Headscale) marshalMapResponse(
	resp interface{},
	machineKey key.MachinePublic,
	compression string,
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
		} else {
			respBody = jsonBody
		}
	}

	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}
