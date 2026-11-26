package dockertestutil

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"path"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const filePerm = 0o644

func WriteLog(
	pool *dockertest.Pool,
	resource *dockertest.Resource,
	stdout io.Writer,
	stderr io.Writer,
) error {
	return pool.Client.Logs(
		docker.LogsOptions{
			Context:      context.TODO(),
			Container:    resource.Container.ID,
			OutputStream: stdout,
			ErrorStream:  stderr,
			Tail:         "all",
			RawTerminal:  false,
			Stdout:       true,
			Stderr:       true,
			Follow:       false,
			Timestamps:   false,
		},
	)
}

func SaveLog(
	pool *dockertest.Pool,
	resource *dockertest.Resource,
	basePath string,
) (string, string, error) {
	err := os.MkdirAll(basePath, os.ModePerm)
	if err != nil {
		return "", "", err
	}

	var stdout, stderr bytes.Buffer

	err = WriteLog(pool, resource, &stdout, &stderr)
	if err != nil {
		return "", "", err
	}

	log.Printf("Saving logs for %s to %s\n", resource.Container.Name, basePath)

	stdoutPath := path.Join(basePath, resource.Container.Name+".stdout.log")

	// CI uploads these: a container's own log carries what its program
	// prints, such as tailscaled's AuthURL with an auth ID.
	err = os.WriteFile(
		stdoutPath,
		[]byte(Redact(stdout.String())),
		filePerm,
	)
	if err != nil {
		return "", "", err
	}

	stderrPath := path.Join(basePath, resource.Container.Name+".stderr.log")

	err = os.WriteFile(
		stderrPath,
		[]byte(Redact(stderr.String())),
		filePerm,
	)
	if err != nil {
		return "", "", err
	}

	return stdoutPath, stderrPath, nil
}
