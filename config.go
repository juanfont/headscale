package headscale

import (
	"crypto/tls"
	"io/fs"
	"net/url"
	"time"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

// Config contains the initial Headscale configuration.
type Config struct {
	ServerURL                      string
	Addr                           string
	MetricsAddr                    string
	GRPCAddr                       string
	GRPCAllowInsecure              bool
	EphemeralNodeInactivityTimeout time.Duration
	IPPrefixes                     []netaddr.IPPrefix
	PrivateKeyPath                 string
	BaseDomain                     string

	DERP DERPConfig

	DBtype string
	DBpath string
	DBhost string
	DBport int
	DBname string
	DBuser string
	DBpass string

	TLSLetsEncryptListen        string
	TLSLetsEncryptHostname      string
	TLSLetsEncryptCacheDir      string
	TLSLetsEncryptChallengeType string

	TLSCertPath       string
	TLSKeyPath        string
	TLSClientAuthMode tls.ClientAuthType

	ACMEURL   string
	ACMEEmail string

	DNSConfig *tailcfg.DNSConfig

	UnixSocket           string
	UnixSocketPermission fs.FileMode

	OIDC OIDCConfig

	LogTail LogTailConfig

	CLI CLIConfig

	ACL ACLConfig
}

type OIDCConfig struct {
	Issuer           string
	ClientID         string
	ClientSecret     string
	Scope            []string
	ExtraParams      map[string]string
	AllowedDomains   []string
	AllowedUsers     []string
	StripEmaildomain bool
}

type DERPConfig struct {
	ServerEnabled    bool
	ServerRegionID   int
	ServerRegionCode string
	ServerRegionName string
	STUNAddr         string
	URLs             []url.URL
	Paths            []string
	AutoUpdate       bool
	UpdateFrequency  time.Duration
}

type LogTailConfig struct {
	Enabled bool
}

type CLIConfig struct {
	Address  string
	APIKey   string
	Timeout  time.Duration
	Insecure bool
}

type ACLConfig struct {
	PolicyPath string
}
