package integrationutil

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"path/filepath"

	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func WriteFileToContainer(
	pool *dockertest.Pool,
	container *dockertest.Resource,
	path string,
	data []byte,
) error {
	dirPath, fileName := filepath.Split(path)

	file := bytes.NewReader(data)

	buf := bytes.NewBuffer([]byte{})

	tarWriter := tar.NewWriter(buf)

	header := &tar.Header{
		Name: fileName,
		Size: file.Size(),
		// Mode:    int64(stat.Mode()),
		// ModTime: stat.ModTime(),
	}

	err := tarWriter.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("failed write file header to tar: %w", err)
	}

	_, err = io.Copy(tarWriter, file)
	if err != nil {
		return fmt.Errorf("failed to copy file to tar: %w", err)
	}

	err = tarWriter.Close()
	if err != nil {
		return fmt.Errorf("failed to close tar: %w", err)
	}

	// Ensure the directory is present inside the container
	_, _, err = dockertestutil.ExecuteCommand(
		container,
		[]string{"mkdir", "-p", dirPath},
		[]string{},
	)
	if err != nil {
		return fmt.Errorf("failed to ensure directory: %w", err)
	}

	err = pool.Client.UploadToContainer(
		container.Container.ID,
		docker.UploadToContainerOptions{
			NoOverwriteDirNonDir: false,
			Path:                 dirPath,
			InputStream:          bytes.NewReader(buf.Bytes()),
		},
	)
	if err != nil {
		return err
	}

	return nil
}
