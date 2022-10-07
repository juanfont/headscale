package http_utils

import (
	"net/http"
	re "regexp"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// CharWhitelistMiddlewareGenerator is an attempt to make it easier to add character whitelist checks to gorilla mux routes.
// Usage pattern is Route().Use(httpu.CharWhitelistMiddlewareGenerator(re.MustCompile(`re_str`), `keyName`, `logStr`))
// re_str: regular expression to compile and evaluate against
// keyName: name of the key that gorilla was told to capture during URL parsing
// logStr: message to print to log in the event of a whitelist failure

func CharWhitelistMiddlewareGenerator(matchExp *re.Regexp, keyName string, logStr string) mux.MiddlewareFunc {
	return mux.MiddlewareFunc(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			vars := mux.Vars(req)
			toValidate := vars[keyName]

			if !matchExp.Match([]byte(toValidate)) {
				// Characters that are outside of the required set have been supplied, do not serve content.
				log.Warn().Str("WhitelistValidateFail", toValidate).Msg("Failed whitelist validation: " + logStr)

				writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
				writer.WriteHeader(http.StatusUnauthorized)
				_, err := writer.Write([]byte("Unauthorized"))
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Msg("Failed to write response")
				}
			} else {
				// Allow processing of content to continue.
				next.ServeHTTP(writer, req)
			}
		})
	})
}

// LengthRequirementMiddlewareGenerator is an attempt to make it easier to add specific length requirements for keys gorilla mux routes.
// Usage pattern is Route().Use(httpu.LengthRequirementMiddlewareGenerator(`keyLen`, `keyName`, `logStr`))
// keyLen: the number of bytes expected in the key argument.
// keyName: name of the key that gorilla was told to capture during URL parsing
// logStr: message to print to log in the event of a whitelist failure

func LengthRequirementMiddlewareGenerator(keyLen uint, keyName string, logStr string) mux.MiddlewareFunc {
	return mux.MiddlewareFunc(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			vars := mux.Vars(req)
			toValidate := vars[keyName]

			if len(toValidate) != int(keyLen) {
				// Characters that are outside of the required set have been supplied, do not serve content.
				log.Warn().Str("WhitelistValidateFail", toValidate).Msg("Failed whitelist validation: " + logStr)

				writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
				writer.WriteHeader(http.StatusUnauthorized)
				_, err := writer.Write([]byte("Unauthorized"))
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Msg("Failed to write response")
				}
			} else {
				// Allow processing of content to continue.
				next.ServeHTTP(writer, req)
			}
		})
	})
}
