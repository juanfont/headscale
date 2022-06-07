package headscale

import (
	"io/ioutil"
	"os"
	"testing"

	"gopkg.in/check.v1"
	"inet.af/netaddr"
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
	tmpDir, err = ioutil.TempDir("", "autoygg-client-test")
	if err != nil {
		c.Fatal(err)
	}
	cfg := Config{
		IPPrefixes: []netaddr.IPPrefix{
			netaddr.MustParseIPPrefix("10.27.0.0/23"),
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

// Enusre an error is returned when an invalid auth mode
// is supplied.
func (s *Suite) TestInvalidClientAuthMode(c *check.C) {
	_, isValid := LookupTLSClientAuthMode("invalid")
	c.Assert(isValid, check.Equals, false)
}

// Ensure that all client auth modes return a nil error.
func (s *Suite) TestAuthModes(c *check.C) {
	modes := []string{"disabled", "relaxed", "enforced"}

	for _, v := range modes {
		_, isValid := LookupTLSClientAuthMode(v)
		c.Assert(isValid, check.Equals, true)
	}
}
