package util

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fileWatch is a watch whose settle time the test ends.
type fileWatch struct {
	changes atomic.Int64
	armed   atomic.Int64
	quiet   chan time.Time
	latest  chan time.Time
	read    chan struct{}
}

// watch watches path with a settle time that ends when the test says so.
func watch(t *testing.T, path, last string) *fileWatch {
	t.Helper()

	fw := &fileWatch{quiet: make(chan time.Time), latest: make(chan time.Time), read: make(chan struct{})}
	after := func(d time.Duration) <-chan time.Time {
		if d == watchLatest {
			return fw.latest
		}

		fw.armed.Add(1)

		return fw.quiet
	}

	require.NoError(t, watchFile(t.Context(), path, []byte(last), func() { fw.changes.Add(1) }, after, func() { fw.read <- struct{}{} }))

	return fw
}

// settle ends the settle time the watch armed, and returns when the watch
// read the file; it blocks until one is armed.
func (fw *fileWatch) settle(t *testing.T) {
	t.Helper()
	fw.fire(t, fw.quiet, "settle")
}

// fire ends the timer of ch, and returns when the watch read the file.
func (fw *fileWatch) fire(t *testing.T, ch chan time.Time, what string) {
	t.Helper()

	timeout := time.After(10 * time.Second)

	select {
	case ch <- time.Time{}:
	case <-timeout:
		t.Fatalf("the watch armed no %s time", what)
	}

	select {
	case <-fw.read:
	case <-timeout:
		t.Fatal("the watch did not read the file")
	}
}

// after runs op, waits until an event of it counted, ends the settle time,
// and wants that many changes.
func (fw *fileWatch) after(t *testing.T, op func(), want int64, msg string) {
	t.Helper()

	armed := fw.armed.Load()

	op()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Greater(c, fw.armed.Load(), armed)
	}, 10*time.Second, 5*time.Millisecond, "%s: no event counted", msg)

	fw.settle(t)
	require.Equal(t, want, fw.changes.Load(), msg)
}

func write(t *testing.T, path, text string) func() {
	t.Helper()

	return func() { require.NoError(t, os.WriteFile(path, []byte(text), 0o600)) }
}

func TestWatchFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.hujson")
	write(t, path, "one")()

	fw := watch(t, path, "one")
	fw.settle(t)

	fw.after(t, write(t, path, "two"), 1, "a write in place")

	fw.after(t, func() {
		tmp := filepath.Join(dir, ".policy.hujson.swp")
		write(t, tmp, "three")()
		require.NoError(t, os.Rename(tmp, path))
	}, 2, "a file renamed over it; the file beside it is not watched")

	fw.after(t, func() {
		require.NoError(t, os.Chmod(path, 0o640))
		write(t, filepath.Join(dir, "other"), "x")()
	}, 2, "a mode change and another file are no change")

	fw.after(t, write(t, path, ""), 3, "an empty file that stays")
	fw.after(t, write(t, path, "four"), 4, "a file written after it was empty")
	fw.after(t, func() { require.NoError(t, os.Remove(path)) }, 5, "a removal")
	fw.after(t, write(t, path, "four"), 6, "the same text back after a removal")
}

func TestWatchFileReadAtStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.hujson")
	write(t, path, "new")()

	fw := watch(t, path, "old")
	fw.settle(t)
	require.Equal(t, int64(1), fw.changes.Load(), "a change between the caller's read and the watch")
}

// TestWatchFileBurst: saves that arrive together are one change, read when
// the file is quiet.
func TestWatchFileBurst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.hujson")
	write(t, path, "one")()

	fw := watch(t, path, "one")
	fw.settle(t)

	for _, text := range []string{"", "tw", "two"} {
		armed := fw.armed.Load()

		write(t, path, text)()

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Greater(c, fw.armed.Load(), armed)
		}, 10*time.Second, 5*time.Millisecond)

		assert.Zero(t, fw.changes.Load(), "read before the file was quiet")
	}

	fw.settle(t)
	require.Equal(t, int64(1), fw.changes.Load())
}

// TestWatchFileDirectoryBack: config management that replaces the
// directory of the file.
func TestWatchFileDirectoryBack(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "conf")
	path := filepath.Join(conf, "policy.hujson")
	require.NoError(t, os.Mkdir(conf, 0o700))
	write(t, path, "A")()

	fw := watch(t, path, "A")
	fw.settle(t)

	fw.after(t, write(t, path, "B"), 1, "a write")
	fw.after(t, func() { require.NoError(t, os.RemoveAll(conf)) }, 2, "the directory removed")
	fw.after(t, func() {
		require.NoError(t, os.Mkdir(conf, 0o700))
		write(t, path, "C")()
	}, 3, "the directory made again, with a file")
	fw.after(t, write(t, path, "D"), 4, "a write in the new directory")
}

// TestWatchFileSymlinkSwap: a Kubernetes config map is a link to a link to a
// directory, swapped by renaming a new link over the old one. NixOS swaps
// /etc/static, a link to a directory above the file's own link.
func TestWatchFileSymlinkSwap(t *testing.T) {
	t.Run("config map", func(t *testing.T) {
		dir := t.TempDir()

		for name, text := range map[string]string{"..v1": "one", "..v2": "two"} {
			require.NoError(t, os.Mkdir(filepath.Join(dir, name), 0o700))
			write(t, filepath.Join(dir, name, "policy.hujson"), text)()
		}

		require.NoError(t, os.Symlink("..v1", filepath.Join(dir, "..data")))
		require.NoError(t, os.Symlink("..data/policy.hujson", filepath.Join(dir, "policy.hujson")))

		fw := watch(t, filepath.Join(dir, "policy.hujson"), "one")
		fw.settle(t)

		fw.after(t, func() {
			require.NoError(t, os.Symlink("..v2", filepath.Join(dir, "..data_tmp")))
			require.NoError(t, os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")))
		}, 1, "the swap of ..data")

		fw.after(t, write(t, filepath.Join(dir, "..v2", "policy.hujson"), "three"), 2, "a write in the new target is watched")
	})

	t.Run("a link to a directory above the file", func(t *testing.T) {
		root := t.TempDir()

		for name, text := range map[string]string{"gen1": "one", "gen2": "two"} {
			require.NoError(t, os.MkdirAll(filepath.Join(root, name, "headscale"), 0o700))
			write(t, filepath.Join(root, name, "headscale", "policy.hujson"), text)()
		}

		etc := filepath.Join(root, "etc")
		require.NoError(t, os.MkdirAll(filepath.Join(etc, "headscale"), 0o700))
		require.NoError(t, os.Symlink(filepath.Join(root, "gen1"), filepath.Join(etc, "static")))
		require.NoError(t, os.Symlink(filepath.Join(etc, "static", "headscale", "policy.hujson"), filepath.Join(etc, "headscale", "policy.hujson")))

		fw := watch(t, filepath.Join(etc, "headscale", "policy.hujson"), "one")
		fw.settle(t)

		fw.after(t, func() {
			require.NoError(t, os.Symlink(filepath.Join(root, "gen2"), filepath.Join(etc, ".static.tmp")))
			require.NoError(t, os.Rename(filepath.Join(etc, ".static.tmp"), filepath.Join(etc, "static")))
		}, 1, "the swap of /etc/static")
	})
}

// TestWatchFileNotStarved: a file saved more often than the settle time is
// read at the latest time after the first save of the burst.
func TestWatchFileNotStarved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.hujson")
	write(t, path, "zero")()

	fw := watch(t, path, "zero")
	fw.settle(t)

	for i, text := range []string{"one", "two", "three"} {
		armed := fw.armed.Load()

		write(t, path, text)()

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Greater(c, fw.armed.Load(), armed)
		}, 10*time.Second, 5*time.Millisecond, "save %d: no event counted", i)
	}

	require.Zero(t, fw.changes.Load(), "no read while the burst goes on")

	fw.fire(t, fw.latest, "latest")
	require.Equal(t, int64(1), fw.changes.Load(), "read at the latest time")
}
