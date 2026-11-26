package util

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
)

// maxLinkHops bounds the symlinks followed to a watched file, as the kernel
// does.
const maxLinkHops = 40

// watchSettle is how long a file must be quiet before it is read: an editor
// truncates and then writes, config management removes a directory and
// makes it again, and each step alone is a file nobody meant.
const watchSettle = 500 * time.Millisecond

// watchLatest bounds a burst: a file saved more often than the settle time
// is read this long after the first save of the burst all the same.
const watchLatest = 3 * time.Second

// WatchFile calls changed each time what path reads changes, until ctx ends:
// a write in place, a file renamed over it, a symlink on the way to it that
// is swapped (a Kubernetes config map, NixOS's /etc/static), a removal, a
// new file, and its directory removed and made again. last is what path read
// when the caller read it; the file is read once when the watch starts, so a
// change before it is not lost. The file is read when it has been quiet for
// a settle time, or at the latest a while after a burst began, so a burst of
// saves is one call and a file saved without pause is still read, and an
// empty file that
// stays is a change like any other. A watch on the file itself would end
// with the first file that replaces it, so the directories that hold the
// file and each symlink on the way are watched, or while one is gone its
// nearest ancestor, and an event counts when it names one of those names or
// a directory above one. changed runs on one goroutine, never twice at once.
func WatchFile(ctx context.Context, path string, last []byte, changed func()) error {
	return watchFile(ctx, path, last, changed, time.After, func() {})
}

// watchFile is [WatchFile] with its timers from after: the settle time,
// which every event that counts arms anew, and the latest time, armed by the
// first event of a burst. read runs after each read of the file.
func watchFile(ctx context.Context, path string, last []byte, changed func(), after func(time.Duration) <-chan time.Time, read func()) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}

	path, err = filepath.Abs(path)
	if err != nil {
		_ = w.Close()

		return fmt.Errorf("resolving %s: %w", path, err)
	}

	var names []string

	// rewatch reports whether the directory of path itself is watched.
	rewatch := func() bool {
		names = linkChain(path)
		held := map[string]bool{}

		for _, name := range names {
			held[holdDir(w, filepath.Dir(name))] = true
		}

		// A directory that is back frees the watch on its ancestor.
		for _, d := range w.WatchList() {
			if !held[d] {
				_ = w.Remove(d)
			}
		}

		return held[filepath.Dir(path)]
	}

	if !rewatch() {
		_ = w.Close()

		return fmt.Errorf("watching %s: %w", filepath.Dir(path), os.ErrNotExist)
	}

	counts := func(name string) bool {
		return slices.ContainsFunc(names, func(n string) bool {
			return n == name || strings.HasPrefix(n, name+string(filepath.Separator))
		})
	}

	sum := func() [sha256.Size]byte {
		b, err := os.ReadFile(path)
		if err != nil {
			// Distinct from every content: a file that comes back as it
			// was is a change.
			return sha256.Sum256([]byte("\x00unreadable:" + err.Error()))
		}

		return sha256.Sum256(b)
	}

	seen := sha256.Sum256(last)

	go func() {
		defer w.Close()

		// Armed at the start, so the file is read once then.
		quiet := after(watchSettle)

		var latest <-chan time.Time

		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}

				if !counts(ev.Name) {
					continue
				}

				rewatch()

				quiet = after(watchSettle)
				if latest == nil {
					latest = after(watchLatest)
				}
			case <-quiet:
				quiet, latest = nil, nil

				if now := sum(); now != seen {
					seen = now

					changed()
				}

				read()
			case <-latest:
				quiet, latest = nil, nil

				if now := sum(); now != seen {
					seen = now

					changed()
				}

				read()
			case err, ok := <-w.Errors:
				if !ok {
					return
				}

				log.Error().Err(err).Str("path", path).Msg("watching a file")
			}
		}
	}()

	return nil
}

// holdDir watches dir, or while dir is gone its nearest ancestor, and
// returns the directory it watches; "" when none can be.
func holdDir(w *fsnotify.Watcher, dir string) string {
	held := dir
	for w.Add(held) != nil {
		up := filepath.Dir(held)
		if up == held {
			return ""
		}

		held = up
	}

	// A directory made before the ancestor's watch held sent it no event,
	// so the way down is tried again; one made after sends one.
	for held != dir {
		rel, _ := filepath.Rel(held, dir)
		next := filepath.Join(held, strings.Split(rel, string(filepath.Separator))[0])

		if w.Add(next) != nil {
			return held
		}

		held = next
	}

	return held
}

// linkChain is path, every symlink on the way from it to the file it names,
// and that file, each as an absolute path. A swap of any of them changes
// what path reads.
func linkChain(path string) []string {
	chain := []string{path}
	rest := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	cur := "/"

	for hops := 0; len(rest) > 0; {
		next := filepath.Join(cur, rest[0])
		rest = rest[1:]

		target, err := os.Readlink(next)
		if err != nil {
			cur = next

			continue
		}

		hops++
		if hops > maxLinkHops {
			break
		}

		chain = append(chain, next)

		if !filepath.IsAbs(target) {
			target = filepath.Join(cur, target)
		}

		rest = append(strings.Split(strings.TrimPrefix(filepath.Clean(target), "/"), "/"), rest...)
		cur = "/"
	}

	return append(chain, cur)
}
