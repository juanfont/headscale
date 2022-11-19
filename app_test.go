package headscale

import (
	"net/netip"
	"os"
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct{}

var (
	tmpDir string
	app    Headscale
)

func (s *Suite) SetUpTest(c *check.C) {
	s.ResetDB(c)
}

func (s *Suite) TearDownTest(c *check.C) {
	os.RemoveAll(tmpDir)
}

func (s *Suite) ResetDB(c *check.C) {
	if len(tmpDir) != 0 {
		os.RemoveAll(tmpDir)
	}
	var err error
	tmpDir, err = os.MkdirTemp("", "autoygg-client-test")
	if err != nil {
		c.Fatal(err)
	}
	cfg := Config{
		IPPrefixes: []netip.Prefix{
			netip.MustParsePrefix("10.27.0.0/23"),
		},
	}

	app = Headscale{
		cfg:      &cfg,
		dbType:   "sqlite3",
		dbString: tmpDir + "/headscale_test.db",
	}
	err = app.initDB()
	if err != nil {
		c.Fatal(err)
	}
	db, err := app.openDB()
	if err != nil {
		c.Fatal(err)
	}
	app.db = db
}
