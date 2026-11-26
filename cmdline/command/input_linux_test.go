package command

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestDiscardInput: a line typed on a terminal and not yet read is gone
// after discardInput; what is typed after it is read.
func TestDiscardInput(t *testing.T) {
	t.Parallel()

	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer ptmx.Close()

	m := int(ptmx.Fd()) //nolint:gosec // a file descriptor fits an int
	require.NoError(t, unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0))

	n, err := unix.IoctlGetInt(m, unix.TIOCGPTN)
	require.NoError(t, err)

	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err)

	defer pts.Close()

	fd := int(pts.Fd()) //nolint:gosec // a file descriptor fits an int

	// readable waits, as long as wait, for a line to read.
	readable := func(wait int) bool {
		//nolint:gosec // a file descriptor fits an int32
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

		_, err := unix.Poll(fds, wait)
		require.NoError(t, err)

		return fds[0].Revents&unix.POLLIN != 0
	}

	_, err = ptmx.WriteString("y\n")
	require.NoError(t, err)
	require.True(t, readable(-1), "the typed line arrives")

	discardInput(fd)
	require.False(t, readable(0), "the typed line is gone")

	_, err = ptmx.WriteString("n\n")
	require.NoError(t, err)

	buf := make([]byte, 8)
	got, err := pts.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "n\n", string(buf[:got]), "what is typed after is read")
}
