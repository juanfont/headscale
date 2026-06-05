package dns

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestUpdateRecordsDoesNotBlockShutdown ensures updateRecords does not park
// forever on the update channel during shutdown. The send must release the
// write lock first and abort on closeCh, otherwise the Run goroutine leaks and
// holds the lock indefinitely when no consumer is draining the channel.
func TestUpdateRecordsDoesNotBlockShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "extra.json")
	require.NoError(t, os.WriteFile(path,
		[]byte(`[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`), 0o600))

	er, err := NewExtraRecordsManager(path)
	require.NoError(t, err)

	defer er.watcher.Close()

	// Change the file so updateRecords passes the unchanged-hash guard and
	// reaches the send with no consumer draining UpdateCh.
	require.NoError(t, os.WriteFile(path,
		[]byte(`[{"name":"b.example.com","type":"A","value":"100.64.0.2"}]`), 0o600))

	done := make(chan struct{})

	go func() {
		er.updateRecords()
		close(done)
	}()

	er.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("updateRecords parked on a blocking send and did not return after Close")
	}
}
