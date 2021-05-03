package headscale

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	_ "github.com/jinzhu/gorm/dialects/sqlite" // sql driver

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct{}

var tmpDir string
var h Headscale

func (s *Suite) SetUpSuite(c *check.C) {
	var err error
	tmpDir, err = ioutil.TempDir("", "autoygg-client-test")
	if err != nil {
		c.Fatal(err)
	}
	fmt.Printf("tmpDir is %s\n", tmpDir)
	cfg := Config{}

	h = Headscale{
		cfg:      cfg,
		dbType:   "sqlite3",
		dbString: tmpDir + "/headscale_test.db",
	}
	err = h.initDB()
	if err != nil {
		c.Fatal(err)
	}
}

func (s *Suite) TearDownSuite(c *check.C) {
	os.RemoveAll(tmpDir)
}

func (*Suite) TestCreatePreAuthKey(c *check.C) {
	_, err := h.CreatePreAuthKey("bogus", true, nil)
	c.Assert(err, check.NotNil)

	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	k, err := h.CreatePreAuthKey(n.Name, true, nil)
	c.Assert(err, check.IsNil)

	// Did we get a valid key?
	c.Assert(k.Key, check.NotNil)
	c.Assert(len(k.Key), check.Equals, 48)

	// Make sure the Namespace association is populated
	c.Assert(k.Namespace.Name, check.Equals, n.Name)

	_, err = h.GetPreAuthKeys("bogus")
	c.Assert(err, check.NotNil)

	keys, err := h.GetPreAuthKeys(n.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(*keys), check.Equals, 1)

	// Make sure the Namespace association is populated
	c.Assert((*keys)[0].Namespace.Name, check.Equals, n.Name)
}
