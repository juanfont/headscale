package util

import "github.com/rs/zerolog/log"

func LogErr(err error, msg string) {
	log.Error().Caller().Err(err).Msg(msg)
}
