package k3sic

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func helmTestArchive(t *testing.T, goarch string, body []byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "linux-" + goarch + "/helm",
		Mode: 0o755,
		Size: int64(len(body)),
	}))
	_, err := tw.Write(body)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	return buf.Bytes()
}

func TestExtractHelmBinaryVerifiesArchive(t *testing.T) {
	archive := helmTestArchive(t, "amd64", []byte("helm-binary"))
	wantHash := fmt.Sprintf("%x", sha256.Sum256(archive))

	got, err := extractHelmBinary(archive, "amd64", wantHash)
	require.NoError(t, err)
	assert.Equal(t, []byte("helm-binary"), got)

	archive[len(archive)-1] ^= 1
	_, err = extractHelmBinary(archive, "amd64", wantHash)
	require.ErrorIs(t, err, errHelmChecksum)
}

func TestExtractHelmBinaryRejectsOversizedMember(t *testing.T) {
	var buf bytes.Buffer

	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "linux-amd64/helm",
		Mode: 0o755,
		Size: maxHelmBinarySize + 1,
	}))
	require.Error(t, tw.Close())
	require.NoError(t, gz.Close())

	archive := buf.Bytes()
	wantHash := fmt.Sprintf("%x", sha256.Sum256(archive))
	_, err := extractHelmBinary(archive, "amd64", wantHash)
	require.ErrorIs(t, err, errHelmBinaryTooLarge)
}

func TestHelmArchiveSHA256RejectsUnsupportedArchitecture(t *testing.T) {
	_, err := helmArchiveSHA256("riscv64")
	require.ErrorIs(t, err, errHelmUnsupportedArch)
}
