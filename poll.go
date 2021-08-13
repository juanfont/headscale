package headscale

import (
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

func (h *Headscale) PollNetMapStream(
	c *gin.Context,
	m Machine,
	req tailcfg.MapRequest,
	mKey wgkey.Key,
	pollData chan []byte,
	update chan []byte,
	cancelKeepAlive chan []byte,
) {

	go h.keepAlive(cancelKeepAlive, pollData, mKey, req, m)

	c.Stream(func(w io.Writer) bool {
		log.Trace().
			Str("handler", "PollNetMapStream").
			Str("machine", m.Name).
			Msg("Waiting for data to stream...")
		select {

		case data := <-pollData:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", m.Name).
				Int("bytes", len(data)).
				Msg("Sending data received via pollData channel")
			_, err := w.Write(data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", m.Name).
					Err(err).
					Msg("Cannot write data")
			}
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", m.Name).
				Int("bytes", len(data)).
				Msg("Data from pollData channel written successfully")
			now := time.Now().UTC()
			m.LastSeen = &now
			h.db.Save(&m)
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", m.Name).
				Int("bytes", len(data)).
				Msg("Machine updated successfully after sending pollData")
			return true

		case <-update:
			log.Debug().
				Str("handler", "PollNetMapStream").
				Str("machine", m.Name).
				Msg("Received a request for update")
			data, err := h.getMapResponse(mKey, req, m)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", m.Name).
					Err(err).
					Msg("Could not get the map update")
			}
			_, err = w.Write(*data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", m.Name).
					Err(err).
					Msg("Could not write the map response")
			}
			return true

		case <-c.Request.Context().Done():
			log.Info().
				Str("handler", "PollNetMapStream").
				Str("machine", m.Name).
				Msg("The client has closed the connection")
			now := time.Now().UTC()
			m.LastSeen = &now
			h.db.Save(&m)
			cancelKeepAlive <- []byte{}
			h.clientsPolling.Delete(m.ID)
			close(update)
			return false
		}
	})
}
