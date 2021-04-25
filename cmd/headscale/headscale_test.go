package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct{}

func (s *Suite) SetUpSuite(c *check.C) {
}

func (s *Suite) TearDownSuite(c *check.C) {

}

func (*Suite) TestConfigLoading(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "headscale")
	if err != nil {
		c.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path, err := os.Getwd()
	if err != nil {
		c.Fatal(err)
	}

	// Symlink the example config file
	err = os.Symlink(filepath.Clean(path+"/../../config.json.example"), filepath.Join(tmpDir, "config.json"))
	if err != nil {
		c.Fatal(err)
	}

	// Load config
	loadConfig(tmpDir)

	// Test that config file was interpreted correctly
	c.Assert(viper.GetString("server_url"), check.Equals, "http://192.168.1.12:8000")
	c.Assert(viper.GetString("listen_addr"), check.Equals, "0.0.0.0:8000")
	c.Assert(viper.GetString("derp_map_path"), check.Equals, "derp.yaml")
	c.Assert(viper.GetString("db_port"), check.Equals, "5432")
	c.Assert(viper.GetString("tls_letsencrypt_hostname"), check.Equals, "")
	c.Assert(viper.GetString("tls_letsencrypt_challenge_type"), check.Equals, "HTTP-01")
}
