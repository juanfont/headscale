package apiv0

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// strictQuery reads the query once, with its errors, before the scopes are
// chosen and anything is bound. url.Values drops a pair it cannot decode and
// huma's reader takes one as absent, so dryRun=true% would delete and a
// broken filter list every row. A query that parses is written back in the
// form every later reader decodes alike; one that does not is emptied, so
// no reader finds a value in it, and requestChecks refuses it with the
// errors kept here.
func strictQuery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, errs := parseQuery(r.URL.RawQuery)

		ctx := r.Context()
		if len(errs) > 0 {
			ctx = context.WithValue(ctx, queryErrorsKey, errs)
		}

		// A copy: the router that mounts v0 keeps the URL it was sent.
		u := *r.URL
		u.RawQuery = query.Encode()
		r = r.WithContext(ctx)
		r.URL = &u

		next.ServeHTTP(w, r)
	})
}

// parseQuery is [url.ParseQuery], which also refuses a ; in a pair, with an
// error at each pair it cannot read instead of only the first.
func parseQuery(raw string) (url.Values, []FieldError) {
	query := url.Values{}

	var errs []FieldError

	add := func(e FieldError) {
		if !slices.Contains(errs, e) {
			errs = append(errs, e)
		}
	}

	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}

		k, v, _ := strings.Cut(pair, "=")

		name, err := url.QueryUnescape(k)
		if err != nil || strings.Contains(k, ";") {
			add(
				FieldError{
					Location: "query",
					Message:  "has a parameter name that is not percent-encoded: escape % as %25 and ; as %3B",
				},
			)

			continue
		}

		value, err := url.QueryUnescape(v)
		if err != nil || strings.Contains(v, ";") {
			add(
				FieldError{
					Location: fieldLocation("query." + name),
					Message:  "is not percent-encoded: escape % as %25 and ; as %3B",
				},
			)

			continue
		}

		query.Add(name, value)
	}

	if len(errs) > 0 {
		return url.Values{}, errs
	}

	return query, nil
}
