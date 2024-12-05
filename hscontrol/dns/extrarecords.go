package dns

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

type ExtraRecordsMan struct {
	mu      sync.RWMutex
	records set.Set[tailcfg.DNSRecord]
	watcher *fsnotify.Watcher
	path    string

	updateChan chan []tailcfg.DNSRecord
	closeCh    chan struct{}
	hashes     map[string][32]byte
}

func NewExtraRecordsMan(path string) (*ExtraRecordsMan, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating watcher: %w", err)
	}
	defer watcher.Close()

	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("getting file info: %w", err)
	}

	if fi.IsDir() {
		return nil, fmt.Errorf("path is a directory, only file is supported: %s", path)
	}

	err = watcher.Add(path)
	if err != nil {
		return nil, fmt.Errorf("adding path to watcher: %w", err)
	}

	return &ExtraRecordsMan{
		watcher: watcher,
		path:    path,
		records: set.Set[tailcfg.DNSRecord]{},
		hashes:  map[string][32]byte{},
		closeCh: make(chan struct{}),
	}, nil
}

func (e *ExtraRecordsMan) Records() []tailcfg.DNSRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.records.Slice()
}

func (e *ExtraRecordsMan) Updates() <-chan []tailcfg.DNSRecord {
	return e.updateChan
}

func (e *ExtraRecordsMan) Run() {
	for {
		select {
		case <-e.closeCh:
			return
		case _, ok := <-e.watcher.Events:
			if !ok {
				log.Error().Msgf("error reading file watcher event of channel, records watcher closing")
				return
			}
			e.updateRecords()

		case err, ok := <-e.watcher.Errors:
			if !ok {
				log.Error().Msgf("error reading file watcher event of channel, records watcher closing")
				return
			}
			log.Error().Err(err).Msgf("extra records filewatcher returned error")
		}
	}
}

func (e *ExtraRecordsMan) Close() {
	close(e.closeCh)
}

func (e *ExtraRecordsMan) updateRecords() {
	records, newHash, err := readExtraRecordsFromPath(e.path)
	if err != nil {
		log.Error().Err(err).Msgf("reading extra records from path: %s", e.path)
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// If there has not been any change, ignore the update.
	if oldHash, ok := e.hashes[e.path]; ok {
		if newHash == oldHash {
			return
		}
	}

	e.records = set.SetOf(records)
	e.hashes[e.path] = newHash

	e.updateChan <- e.records.Slice()
}

// readExtraRecordsFromPath reads a JSON file of tailcfg.DNSRecord
// and returns the records and the hash of the file.
func readExtraRecordsFromPath(path string) ([]tailcfg.DNSRecord, [32]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("reading path: %s, err: %w", path, err)
	}

	var records []tailcfg.DNSRecord
	err = json.Unmarshal(b, &records)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("unmarshalling records: %w", err)
	}

	hash := sha256.Sum256(b)

	return records, hash, nil
}
