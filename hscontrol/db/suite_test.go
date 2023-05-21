package db

import (
	"net/netip"
	"os"
	"sync/atomic"
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct{}

var (
	tmpDir string
	db     *HSDatabase

	// channelUpdates counts the number of times
	// either of the channels was notified.
	channelUpdates int32
)

func (s *Suite) SetUpTest(c *check.C) {
	atomic.StoreInt32(&channelUpdates, 0)
	s.ResetDB(c)
}

func (s *Suite) TearDownTest(c *check.C) {
	os.RemoveAll(tmpDir)
}

func notificationSink(c <-chan struct{}) {
	for {
		<-c
		atomic.AddInt32(&channelUpdates, 1)
	}
}

func (s *Suite) ResetDB(c *check.C) {
	if len(tmpDir) != 0 {
		os.RemoveAll(tmpDir)
	}
	var err error
	tmpDir, err = os.MkdirTemp("", "autoygg-client-test")
	if err != nil {
		c.Fatal(err)
	}

	sink := make(chan struct{})

	go notificationSink(sink)

	db, err = NewHeadscaleDatabase(
		"sqlite3",
		tmpDir+"/headscale_test.db",
		false,
		false,
		sink,
		sink,
		[]netip.Prefix{
			netip.MustParsePrefix("10.27.0.0/23"),
		},
		"",
	)
	if err != nil {
		c.Fatal(err)
	}
}
