package dockertestutil

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const dockerHubServer = "https://index.docker.io/v1/"

type CredentialSource string

const (
	CredentialSourceEnv       CredentialSource = "env"
	CredentialSourceConfig    CredentialSource = "config"
	CredentialSourceAnonymous CredentialSource = "anonymous"
)

// Credentials resolves Docker Hub credentials from
// DOCKERHUB_USERNAME/DOCKERHUB_TOKEN, then ~/.docker/config.json, then
// anonymous. The Docker Go SDKs do not read config.json on their own.
func Credentials() (string, string, CredentialSource) {
	if u := os.Getenv("DOCKERHUB_USERNAME"); u != "" {
		return u, os.Getenv("DOCKERHUB_TOKEN"), CredentialSourceEnv
	}

	user, pass, ok := credentialsFromConfig()
	if ok {
		return user, pass, CredentialSourceConfig
	}

	return "", "", CredentialSourceAnonymous
}

// AuthConfiguration returns Docker Hub auth for the dockertest pool.
func AuthConfiguration() docker.AuthConfiguration {
	u, p, _ := Credentials()

	return docker.AuthConfiguration{
		Username:      u,
		Password:      p,
		ServerAddress: dockerHubServer,
	}
}

// RegistryAuth returns base64-encoded credentials for the modern
// Docker SDK's image.PullOptions{RegistryAuth: ...}, or "" when none.
func RegistryAuth() (string, error) {
	u, p, _ := Credentials()
	if u == "" && p == "" {
		return "", nil
	}

	auth := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: u, Password: p}

	b, err := json.Marshal(auth) //nolint:gosec // G117: password field holds the Docker Hub token, intentional
	if err != nil {
		return "", fmt.Errorf("marshalling docker auth: %w", err)
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

// PullWithAuth ensures imageRef is local, pulling with auth and
// retrying transient errors when it is not.
func PullWithAuth(pool *dockertest.Pool, imageRef string) error {
	if img, _ := pool.Client.InspectImage(imageRef); img != nil {
		return nil
	}

	repo, tag := splitImageRef(imageRef)
	auth := AuthConfiguration()

	_, err := backoff.Retry(
		context.Background(),
		func() (struct{}, error) {
			err := pool.Client.PullImage(docker.PullImageOptions{
				Repository: repo,
				Tag:        tag,
			}, auth)
			if err == nil {
				return struct{}{}, nil
			}

			if isPermanentPullError(err) {
				return struct{}{}, backoff.Permanent(err)
			}

			return struct{}{}, fmt.Errorf("pulling %s: %w", imageRef, err)
		},
		backoff.WithBackOff(backoff.NewExponentialBackOff()),
		backoff.WithMaxElapsedTime(60*time.Second),
	)
	if err != nil {
		return fmt.Errorf("pulling %s with auth (source=%s): %w", imageRef, AuthConfiguration().ServerAddress, err)
	}

	return nil
}

func splitImageRef(ref string) (string, string) {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[:i], ref[i+1:]
	}

	return ref, "latest"
}

func isPermanentPullError(err error) bool {
	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "manifest unknown") ||
		strings.Contains(msg, "manifest not found") ||
		strings.Contains(msg, "repository does not exist") ||
		strings.Contains(msg, "name unknown") ||
		strings.Contains(msg, "no such image")
}

// credentialsFromConfig reads the Hub entry from ~/.docker/config.json.
// Credential helpers (osxkeychain etc.) are not supported; use env vars.
func credentialsFromConfig() (string, string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", false
	}

	raw, err := os.ReadFile(filepath.Join(home, ".docker", "config.json"))
	if err != nil {
		return "", "", false
	}

	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}

	err = json.Unmarshal(raw, &cfg)
	if err != nil {
		return "", "", false
	}

	entry, found := cfg.Auths[dockerHubServer]
	if !found || entry.Auth == "" {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}
