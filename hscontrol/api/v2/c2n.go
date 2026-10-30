package apiv2

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"tailscale.com/tailcfg"
)

// c2nTimeout bounds how long a c2n request waits for the node to answer.
// For an update, the node replies once the update has started, not finished.
const c2nTimeout = 30 * time.Second

// sendC2N sends a POST to path on the node's c2n handler, carried in a
// [tailcfg.PingRequest], and waits for the node's HTTP response.
func sendC2N(ctx context.Context, b Backend, nodeID types.NodeID, path string) (*http.Response, error) {
	c2nReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://headscale"+path, nil)
	if err != nil {
		return nil, huma.Error500InternalServerError("building c2n request", err)
	}

	var payload bytes.Buffer

	err = c2nReq.Write(&payload)
	if err != nil {
		return nil, huma.Error500InternalServerError("encoding c2n request", err)
	}

	// The client only answers c2n over Noise, and only an https URL makes
	// its Noise transport dial; the host is not used.
	callback, err := url.Parse(b.Cfg.ServerURL)
	if err != nil {
		return nil, huma.Error500InternalServerError("parsing server_url", err)
	}

	c2nID, responseCh := b.State.RegisterC2N(nodeID)
	defer b.State.CancelC2N(c2nID)

	callback.Scheme = "https"
	callback.Path = "/machine/c2n-response"
	callback.RawQuery = url.Values{"id": {c2nID}}.Encode()

	b.Change(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL:     callback.String(),
		Log:     true,
		Types:   "c2n",
		Payload: payload.Bytes(),
	}))

	timer := time.NewTimer(c2nTimeout)
	defer timer.Stop()

	select {
	case raw, ok := <-responseCh:
		if !ok {
			return nil, huma.Error503ServiceUnavailable("server is shutting down")
		}

		res, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), c2nReq)
		if err != nil {
			return nil, huma.Error502BadGateway("reading c2n response", err)
		}

		if res.StatusCode != http.StatusOK {
			res.Body.Close()

			return nil, huma.Error502BadGateway("device answered c2n request with " + res.Status)
		}

		return res, nil
	case <-timer.C:
		return nil, huma.Error504GatewayTimeout("device did not answer within " + c2nTimeout.String())
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
