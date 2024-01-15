package util

import (
	"github.com/rs/zerolog/log"
	"tailscale.com/types/logger"
)

func LogErr(err error, msg string) {
	log.Error().Caller().Err(err).Msg(msg)
}

func TSLogfWrapper() logger.Logf {
	return func(format string, args ...any) {
		log.Debug().Caller().Msgf(format, args...)
	}
}
