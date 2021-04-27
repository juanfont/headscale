package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
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

	// Load example config, it should load without validation errors
	err = loadConfig(tmpDir)
	c.Assert(err, check.IsNil)

	// Test that config file was interpreted correctly
	c.Assert(viper.GetString("server_url"), check.Equals, "http://192.168.1.12:8000")
	c.Assert(viper.GetString("listen_addr"), check.Equals, "0.0.0.0:8000")
	c.Assert(viper.GetString("derp_map_path"), check.Equals, "derp.yaml")
	c.Assert(viper.GetString("db_port"), check.Equals, "5432")
	c.Assert(viper.GetString("tls_letsencrypt_hostname"), check.Equals, "")
	c.Assert(viper.GetString("tls_letsencrypt_challenge_type"), check.Equals, "HTTP-01")
}

func writeConfig(c *check.C, tmpDir string, configYaml []byte) {
	// Populate a custom config file
	configFile := filepath.Join(tmpDir, "config.yaml")
	err := ioutil.WriteFile(configFile, configYaml, 0644)
	if err != nil {
		c.Fatalf("Couldn't write file %s", configFile)
	}
}

func (*Suite) TestTLSConfigValidation(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "headscale")
	if err != nil {
		c.Fatal(err)
	}
	//defer os.RemoveAll(tmpDir)
	fmt.Println(tmpDir)

	configYaml := []byte("---\ntls_letsencrypt_hostname: \"example.com\"\ntls_letsencrypt_challenge_type: \"\"\ntls_cert_path: \"abc.pem\"")
	writeConfig(c, tmpDir, configYaml)

	// Check configuration validation errors (1)
	err = loadConfig(tmpDir)
	c.Assert(err, check.NotNil)
	// check.Matches can not handle multiline strings
	tmp := strings.ReplaceAll(err.Error(), "\n", "***")
	c.Assert(tmp, check.Matches, ".*Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both.*")
	c.Assert(tmp, check.Matches, ".*Fatal config error: the only supported values for tls_letsencrypt_challenge_type are.*")
	c.Assert(tmp, check.Matches, ".*Fatal config error: server_url must start with https:// or http://.*")
	fmt.Println(tmp)

	// Check configuration validation errors (2)
	configYaml = []byte("---\nserver_url: \"http://192.168.1.12:8000\"\ntls_letsencrypt_hostname: \"example.com\"\ntls_letsencrypt_challenge_type: \"TLS-ALPN-01\"")
	fmt.Printf(string(configYaml))
	writeConfig(c, tmpDir, configYaml)
	err = loadConfig(tmpDir)
	c.Assert(err, check.NotNil)
	c.Assert(err, check.ErrorMatches, "Fatal config error: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, listen_addr must end in :443.*")
}
