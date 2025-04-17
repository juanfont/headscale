package db

import (
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

// TestEphemeralGarbageCollectorGoRoutineLeak is a test for a goroutine leak in EphemeralGarbageCollector().
// It creates a new EphemeralGarbageCollector, schedules several nodes for deletion with a short expiry,
// and verifies that the nodes are deleted when the expiry time passes, and then
// for any leaked goroutines after the garbage collector is closed.
func TestEphemeralGarbageCollectorGoRoutineLeak(t *testing.T) {
	// Count goroutines at the start
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial number of goroutines: %d", initialGoroutines)

	// Basic deletion tracking mechanism
	var deletedIDs []types.NodeID
	var deleteMutex sync.Mutex

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()
		deletedIDs = append(deletedIDs, nodeID)
		deleteMutex.Unlock()
	}

	// Start the GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()

	// Schedule several nodes for deletion with short expiry
	const expiry = 50 * time.Millisecond
	const numNodes = 100

	for i := 1; i <= numNodes; i++ {
		gc.Schedule(types.NodeID(i), expiry)
	}

	// Wait for the scheduled deletions to happen
	time.Sleep(expiry * 2)

	// Check nodes are deleted
	deleteMutex.Lock()
	assert.Equal(t, numNodes, len(deletedIDs), "Not all nodes were deleted")
	deleteMutex.Unlock()

	// Schedule and immediately cancel to test that part of the code
	for i := numNodes + 1; i <= numNodes*2; i++ {
		nodeID := types.NodeID(i)
		gc.Schedule(nodeID, time.Hour)
		gc.Cancel(nodeID)
	}

	// Wait to ensure all goroutines have a chance to start/finish
	time.Sleep(4 * expiry)

	// Close GC
	gc.Close()

	// Wait to ensure all goroutines have finished
	time.Sleep(4 * expiry)

	// Check for leaked goroutines
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final number of goroutines: %d", finalGoroutines)

	// NB: We have to allow for a small number of extra goroutines because of test itself
	assert.LessOrEqual(t, finalGoroutines, initialGoroutines+5,
		"There are significantly more goroutines after GC usage, which suggests a leak")
}

// TestEphemeralGarbageCollectorReschedule is a test for the rescheduling of nodes in EphemeralGarbageCollector().
// It creates a new EphemeralGarbageCollector, schedules a node for deletion with a longer expiry,
// and then reschedules it with a shorter expiry, and verifies that the node is deleted only once.
func TestEphemeralGarbageCollectorReschedule(t *testing.T) {
	// Deletion tracking mechanism
	var deletedIDs []types.NodeID
	var deleteMutex sync.Mutex

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()
		deletedIDs = append(deletedIDs, nodeID)
		deleteMutex.Unlock()
	}

	// Start GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()
	defer gc.Close()

	const shortExpiry = 50 * time.Millisecond
	const longExpiry = 1 * time.Hour

	nodeID := types.NodeID(1)

	// Schedule node for deletion with long expiry
	gc.Schedule(nodeID, longExpiry)

	// Reschedule the same node with a shorter expiry
	gc.Schedule(nodeID, shortExpiry)

	// Wait for deletion
	time.Sleep(shortExpiry * 2)

	// Verify that the node was deleted once
	deleteMutex.Lock()
	assert.Equal(t, 1, len(deletedIDs), "Node should be deleted exactly once")
	assert.Equal(t, nodeID, deletedIDs[0], "The correct node should be deleted")
	deleteMutex.Unlock()
}

// TestEphemeralGarbageCollectorCancelAndReschedule is a test for the cancellation and rescheduling of nodes in EphemeralGarbageCollector().
// It creates a new EphemeralGarbageCollector, schedules a node for deletion, cancels it, and then reschedules it,
// and verifies that the node is deleted only once.
func TestEphemeralGarbageCollectorCancelAndReschedule(t *testing.T) {
	// Deletion tracking mechanism
	var deletedIDs []types.NodeID
	var deleteMutex sync.Mutex

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()
		deletedIDs = append(deletedIDs, nodeID)
		deleteMutex.Unlock()
	}

	// Start the GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()
	defer gc.Close()

	nodeID := types.NodeID(1)
	const expiry = 50 * time.Millisecond

	// Schedule node for deletion
	gc.Schedule(nodeID, expiry)

	// Cancel the scheduled deletion
	gc.Cancel(nodeID)

	// Verify no deletion occurred
	time.Sleep(expiry * 2)
	deleteMutex.Lock()
	assert.Equal(t, 0, len(deletedIDs), "Node should not be deleted after cancellation")
	deleteMutex.Unlock()

	// Reschedule the node
	gc.Schedule(nodeID, expiry)

	// Wait for deletion
	time.Sleep(expiry * 2)

	// Verify that the node deleted
	deleteMutex.Lock()
	assert.Equal(t, 1, len(deletedIDs), "Node should be deleted after rescheduling")
	assert.Equal(t, nodeID, deletedIDs[0], "The correct node should be deleted")
	deleteMutex.Unlock()
}

// TestEphemeralGarbageCollectorCloseBeforeTimerFires is a test for the closing of the EphemeralGarbageCollector before the timer fires.
// It creates a new EphemeralGarbageCollector, schedules a node for deletion, closes the GC, and verifies that the node is not deleted.
func TestEphemeralGarbageCollectorCloseBeforeTimerFires(t *testing.T) {
	// Deletion tracking
	var deletedIDs []types.NodeID
	var deleteMutex sync.Mutex

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()
		deletedIDs = append(deletedIDs, nodeID)
		deleteMutex.Unlock()
	}

	// Start the GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()

	const longExpiry = 1 * time.Hour
	const shortExpiry = 50 * time.Millisecond

	// Schedule node deletion with a long expiry
	gc.Schedule(types.NodeID(1), longExpiry)

	// Close the GC before the timer
	gc.Close()

	// Wait a short time
	time.Sleep(shortExpiry * 2)

	// Verify that no deletion occurred
	deleteMutex.Lock()
	assert.Equal(t, 0, len(deletedIDs), "No node should be deleted when GC is closed before timer fires")
	deleteMutex.Unlock()
}

// TestEphemeralGarbageCollectorScheduleAfterClose verifies that calling Schedule after Close
// is a no-op and doesn't cause any panics, goroutine leaks, or other issues.
func TestEphemeralGarbageCollectorScheduleAfterClose(t *testing.T) {
	// Count initial goroutines to check for leaks
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial number of goroutines: %d", initialGoroutines)

	// Deletion tracking
	var deletedIDs []types.NodeID
	var deleteMutex sync.Mutex
	nodeDeleted := make(chan struct{})

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()
		deletedIDs = append(deletedIDs, nodeID)
		deleteMutex.Unlock()
		close(nodeDeleted) // Signal that deletion happened
	}

	// Start new GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()

	const shortSleep = 50 * time.Millisecond
	const shortSchedule = 20 * time.Millisecond

	// Close GC right away
	gc.Close()

	// Wait a bit to ensure its fully closed
	time.Sleep(shortSleep)

	// Now try to schedule node for deletion
	nodeID := types.NodeID(1)
	gc.Schedule(nodeID, shortSchedule)

	// Wait longer than the scheduled time, enough for node to be deleted if the timer was created
	time.Sleep(shortSleep * 2)

	// Check no node was deleted
	deleteMutex.Lock()
	nodesDeleted := len(deletedIDs)
	deleteMutex.Unlock()
	assert.Equal(t, 0, nodesDeleted, "No nodes should be deleted when Schedule is called after Close")

	// Check for goroutine leaks
	time.Sleep(shortSleep) // Give any potential goroutines time to exit
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final number of goroutines: %d", finalGoroutines)

	// Allow for small fluctuations in goroutine count for testing routines etc
	assert.LessOrEqual(t, finalGoroutines, initialGoroutines+2,
		"There should be no significant goroutine leaks when Schedule is called after Close")
}

// TestEphemeralGarbageCollectorConcurrentScheduleAndClose tests the behavior of the garbage collector
// when Schedule and Close are called concurrently from multiple goroutines.
func TestEphemeralGarbageCollectorConcurrentScheduleAndClose(t *testing.T) {
	// Count initial goroutines
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial number of goroutines: %d", initialGoroutines)

	// Deletion tracking mechanism
	var deletedIDs []types.NodeID
	var deleteMutex sync.Mutex

	deleteFunc := func(nodeID types.NodeID) {
		deleteMutex.Lock()
		deletedIDs = append(deletedIDs, nodeID)
		deleteMutex.Unlock()
	}

	// Start the GC
	gc := NewEphemeralGarbageCollector(deleteFunc)
	go gc.Start()

	// Number of concurrent scheduling goroutines
	const numSchedulers = 10
	const nodesPerScheduler = 50
	const schedulingDuration = 500 * time.Millisecond

	// Use WaitGroup to wait for all scheduling goroutines to finish
	var wg sync.WaitGroup
	wg.Add(numSchedulers + 1) // +1 for the closer goroutine

	// Create a stopper channel to signal scheduling goroutines to stop
	stopScheduling := make(chan struct{})

	// Launch goroutines that continuously schedule nodes
	for i := 0; i < numSchedulers; i++ {
		go func(schedulerID int) {
			defer wg.Done()

			baseNodeID := schedulerID * nodesPerScheduler

			// Keep scheduling nodes until signaled to stop
			for j := 0; j < nodesPerScheduler; j++ {
				select {
				case <-stopScheduling:
					return
				default:
					nodeID := types.NodeID(baseNodeID + j + 1)
					gc.Schedule(nodeID, 1*time.Hour) // Long expiry to ensure it doesn't trigger during test

					// Random (short) sleep to introduce randomness/variability
					time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
				}
			}
		}(i)
	}

	// After a short delay, close the garbage collector while schedulers are still running
	go func() {
		defer wg.Done()
		time.Sleep(schedulingDuration / 2)

		// Close GC
		gc.Close()

		// Signal schedulers to stop
		close(stopScheduling)
	}()

	// Wait for all goroutines to complete
	wg.Wait()

	// Wait a bit longer to allow any any leaked goroutines to do their work
	time.Sleep(100 * time.Millisecond)

	// Check for leaks
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final number of goroutines: %d", finalGoroutines)

	// Allow for a reasonable small variable routine count do to testing
	assert.LessOrEqual(t, finalGoroutines, initialGoroutines+5,
		"There should be no significant goroutine leaks during concurrent Schedule and Close operations")
}
