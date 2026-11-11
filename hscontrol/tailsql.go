package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/juanfont/headscale/hscontrol/db/sqliteconfig"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/tailsql/authorizer"
	"github.com/tailscale/tailsql/server/tailsql"
	"tailscale.com/net/netx"
)

const (
	tailsqlHostname = "tailsql"
	tailsqlTag      = "tag:tailsql"
)

var errTailSQLStatementDenied = errors.New("statement not allowed")

// tailsqlDenied matches statements that write despite a read-only connection:
// ATTACH and VACUUM INTO create files, PRAGMA can lift query_only. Table-valued
// pragma_* functions stay allowed; \b does not split on "_".
var tailsqlDenied = regexp.MustCompile(`(?i)\b(attach|vacuum|pragma)\b`)

func checkTailSQLQuery(q tailsql.Query) (tailsql.Query, error) {
	q, err := tailsql.DefaultCheckQuery(q)
	if err != nil {
		return q, err
	}

	if m := tailsqlDenied.FindString(q.Query); m != "" {
		return q, fmt.Errorf("%w: %s", errTailSQLStatementDenied, m)
	}

	return q, nil
}

// runTailSQLService serves a read-only SQL UI over the database at dbPath as
// a tagged node on headscale's own tailnet, until ctx ends.
func runTailSQLService(
	ctx context.Context,
	st *state.State,
	dial netx.DialFunc,
	controlURL, stateDir, dbPath string,
) error {
	logf := util.TSLogfWrapper()

	dsn, err := sqliteconfig.ReadOnly(dbPath).ToURL()
	if err != nil {
		return fmt.Errorf("tailsql database url: %w", err)
	}

	ts, err := newEmbeddedNode(ctx, st, dial, controlURL, stateDir, tailsqlHostname, tailsqlTag)
	if err != nil {
		return err
	}
	defer ts.Close()

	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("tailsql local client: %w", err)
	}

	tsql, err := tailsql.NewServer(tailsql.Options{
		LocalClient: lc,
		Authorize:   authorizer.ACLGrants(logf),
		CheckQuery:  checkTailSQLQuery,
		Sources: []tailsql.DBSpec{{
			Source: "headscale",
			Label:  "headscale - sqlite",
			Driver: "sqlite",
			URL:    dsn,
			Named: map[string]string{
				"schema": `select * from sqlite_schema`,
			},
		}},
	})
	if err != nil {
		return fmt.Errorf("creating tailsql server: %w", err)
	}
	defer tsql.Close()

	ln80, err := ts.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("tailsql listen :80: %w", err)
	}

	var (
		ln  = ln80
		url = "http://" + tailsqlHostname
	)

	// Headscale sends cert domains only with MagicDNS and dns.certificates.
	if domains := ts.CertDomains(); len(domains) > 0 {
		url = "https://" + domains[0]

		ln, err = ts.ListenTLS("tcp", ":443")
		if err != nil {
			return fmt.Errorf("tailsql listen :443: %w", err)
		}

		go serveTailSQL(ln80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, url+r.RequestURI, http.StatusPermanentRedirect) //nolint:gosec // G710: url is a trusted cert domain
		}))
	}

	go serveTailSQL(ln, tsql.NewMux())

	ip4, ip6 := ts.TailscaleIPs()
	log.Info().
		Str("url", url).
		Stringer("ipv4", ip4).
		Stringer("ipv6", ip6).
		Msgf("tailsql ready; grant %s the app capability tailscale.com/cap/tailsql to use it", tailsqlTag)

	<-ctx.Done()

	return nil
}

func serveTailSQL(ln net.Listener, h http.Handler) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	_ = srv.Serve(ln)
}
