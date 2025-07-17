package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// ContainerStats represents statistics for a single container
type ContainerStats struct {
	ContainerID   string
	ContainerName string
	Stats         []StatsSample
	mutex         sync.RWMutex
}

// StatsSample represents a single stats measurement
type StatsSample struct {
	Timestamp time.Time
	CPUUsage  float64 // CPU usage percentage
	MemoryMB  float64 // Memory usage in MB
}

// StatsCollector manages collection of container statistics
type StatsCollector struct {
	client            *client.Client
	containers        map[string]*ContainerStats
	stopChan          chan struct{}
	wg                sync.WaitGroup
	mutex             sync.RWMutex
	collectionStarted bool
}

// NewStatsCollector creates a new stats collector instance
func NewStatsCollector() (*StatsCollector, error) {
	cli, err := createDockerClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return &StatsCollector{
		client:     cli,
		containers: make(map[string]*ContainerStats),
		stopChan:   make(chan struct{}),
	}, nil
}

// StartCollection begins monitoring all containers and collecting stats for hs- and ts- containers with matching run ID
func (sc *StatsCollector) StartCollection(ctx context.Context, runID string, verbose bool) error {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.collectionStarted {
		return fmt.Errorf("stats collection already started")
	}

	sc.collectionStarted = true

	// Start monitoring existing containers
	sc.wg.Add(1)
	go sc.monitorExistingContainers(ctx, runID, verbose)

	// Start Docker events monitoring for new containers
	sc.wg.Add(1)
	go sc.monitorDockerEvents(ctx, runID, verbose)

	if verbose {
		log.Printf("Started container monitoring for run ID %s", runID)
	}

	return nil
}

// StopCollection stops all stats collection
func (sc *StatsCollector) StopCollection() {
	// Check if already stopped without holding lock
	sc.mutex.RLock()
	if !sc.collectionStarted {
		sc.mutex.RUnlock()
		return
	}
	sc.mutex.RUnlock()

	// Signal stop to all goroutines
	close(sc.stopChan)
	
	// Wait for all goroutines to finish
	sc.wg.Wait()
	
	// Mark as stopped
	sc.mutex.Lock()
	sc.collectionStarted = false
	sc.mutex.Unlock()
}

// monitorExistingContainers checks for existing containers that match our criteria
func (sc *StatsCollector) monitorExistingContainers(ctx context.Context, runID string, verbose bool) {
	defer sc.wg.Done()

	containers, err := sc.client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		if verbose {
			log.Printf("Failed to list existing containers: %v", err)
		}
		return
	}

	for _, cont := range containers {
		if sc.shouldMonitorContainer(cont, runID) {
			sc.startStatsForContainer(ctx, cont.ID, cont.Names[0], verbose)
		}
	}
}

// monitorDockerEvents listens for container start events and begins monitoring relevant containers
func (sc *StatsCollector) monitorDockerEvents(ctx context.Context, runID string, verbose bool) {
	defer sc.wg.Done()

	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("event", "start")
	
	eventOptions := events.ListOptions{
		Filters: filter,
	}

	events, errs := sc.client.Events(ctx, eventOptions)

	for {
		select {
		case <-sc.stopChan:
			return
		case <-ctx.Done():
			return
		case event := <-events:
			if event.Type == "container" && event.Action == "start" {
				// Get container details
				containerInfo, err := sc.client.ContainerInspect(ctx, event.ID)
				if err != nil {
					continue
				}

				// Convert to types.Container format for consistency
				cont := types.Container{
					ID:     containerInfo.ID,
					Names:  []string{containerInfo.Name},
					Labels: containerInfo.Config.Labels,
				}

				if sc.shouldMonitorContainer(cont, runID) {
					sc.startStatsForContainer(ctx, cont.ID, cont.Names[0], verbose)
				}
			}
		case err := <-errs:
			if verbose {
				log.Printf("Error in Docker events stream: %v", err)
			}
			return
		}
	}
}

// shouldMonitorContainer determines if a container should be monitored
func (sc *StatsCollector) shouldMonitorContainer(cont types.Container, runID string) bool {
	// Check if it has the correct run ID label
	if cont.Labels == nil || cont.Labels["hi.run-id"] != runID {
		return false
	}

	// Check if it's an hs- or ts- container
	for _, name := range cont.Names {
		containerName := strings.TrimPrefix(name, "/")
		if strings.HasPrefix(containerName, "hs-") || strings.HasPrefix(containerName, "ts-") {
			return true
		}
	}

	return false
}

// startStatsForContainer begins stats collection for a specific container
func (sc *StatsCollector) startStatsForContainer(ctx context.Context, containerID, containerName string, verbose bool) {
	containerName = strings.TrimPrefix(containerName, "/")

	sc.mutex.Lock()
	// Check if we're already monitoring this container
	if _, exists := sc.containers[containerID]; exists {
		sc.mutex.Unlock()
		return
	}

	sc.containers[containerID] = &ContainerStats{
		ContainerID:   containerID,
		ContainerName: containerName,
		Stats:         make([]StatsSample, 0),
	}
	sc.mutex.Unlock()

	if verbose {
		log.Printf("Starting stats collection for container %s (%s)", containerName, containerID[:12])
	}

	sc.wg.Add(1)
	go sc.collectStatsForContainer(ctx, containerID, verbose)
}

// collectStatsForContainer collects stats for a specific container using Docker API streaming
func (sc *StatsCollector) collectStatsForContainer(ctx context.Context, containerID string, verbose bool) {
	defer sc.wg.Done()

	// Use Docker API streaming stats - much more efficient than CLI
	statsResponse, err := sc.client.ContainerStats(ctx, containerID, true)
	if err != nil {
		if verbose {
			log.Printf("Failed to get stats stream for container %s: %v", containerID[:12], err)
		}
		return
	}
	defer statsResponse.Body.Close()

	decoder := json.NewDecoder(statsResponse.Body)
	var prevStats *container.Stats

	for {
		select {
		case <-sc.stopChan:
			return
		case <-ctx.Done():
			return
		default:
			var stats container.Stats
			if err := decoder.Decode(&stats); err != nil {
				// EOF is expected when container stops or stream ends
				if err.Error() != "EOF" && verbose {
					log.Printf("Failed to decode stats for container %s: %v", containerID[:12], err)
				}
				return
			}

			// Calculate CPU percentage (only if we have previous stats)
			var cpuPercent float64
			if prevStats != nil {
				cpuPercent = calculateCPUPercent(prevStats, &stats)
			}

			// Calculate memory usage in MB
			memoryMB := float64(stats.MemoryStats.Usage) / (1024 * 1024)

			// Store the sample (skip first sample since CPU calculation needs previous stats)
			if prevStats != nil {
				// Get container stats reference without holding the main mutex
				var containerStats *ContainerStats
				var exists bool
				
				sc.mutex.RLock()
				containerStats, exists = sc.containers[containerID]
				sc.mutex.RUnlock()

				if exists && containerStats != nil {
					containerStats.mutex.Lock()
					containerStats.Stats = append(containerStats.Stats, StatsSample{
						Timestamp: time.Now(),
						CPUUsage:  cpuPercent,
						MemoryMB:  memoryMB,
					})
					containerStats.mutex.Unlock()
				}
			}

			// Save current stats for next iteration
			prevStats = &stats
		}
	}
}

// calculateCPUPercent calculates CPU usage percentage from Docker stats
func calculateCPUPercent(prevStats, stats *container.Stats) float64 {
	// CPU calculation based on Docker's implementation
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage) - float64(prevStats.CPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage) - float64(prevStats.CPUStats.SystemUsage)
	
	if systemDelta > 0 && cpuDelta >= 0 {
		// Calculate CPU percentage: (container CPU delta / system CPU delta) * number of CPUs * 100
		numCPUs := float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
		if numCPUs == 0 {
			// Fallback: if PercpuUsage is not available, assume 1 CPU
			numCPUs = 1.0
		}
		return (cpuDelta / systemDelta) * numCPUs * 100.0
	}
	return 0.0
}

// ContainerStatsSummary represents summary statistics for a container
type ContainerStatsSummary struct {
	ContainerName string
	SampleCount   int
	CPU           StatsSummary
	Memory        StatsSummary
}

// MemoryViolation represents a container that exceeded the memory limit
type MemoryViolation struct {
	ContainerName string
	MaxMemoryMB   float64
	LimitMB       float64
}

// StatsSummary represents min, max, and average for a metric
type StatsSummary struct {
	Min     float64
	Max     float64
	Average float64
}

// GetSummary returns a summary of collected statistics
func (sc *StatsCollector) GetSummary() []ContainerStatsSummary {
	// Take snapshot of container references without holding main lock long
	sc.mutex.RLock()
	containerRefs := make([]*ContainerStats, 0, len(sc.containers))
	for _, containerStats := range sc.containers {
		containerRefs = append(containerRefs, containerStats)
	}
	sc.mutex.RUnlock()

	summaries := make([]ContainerStatsSummary, 0, len(containerRefs))

	for _, containerStats := range containerRefs {
		containerStats.mutex.RLock()
		stats := make([]StatsSample, len(containerStats.Stats))
		copy(stats, containerStats.Stats)
		containerName := containerStats.ContainerName
		containerStats.mutex.RUnlock()

		if len(stats) == 0 {
			continue
		}

		summary := ContainerStatsSummary{
			ContainerName: containerName,
			SampleCount:   len(stats),
		}

		// Calculate CPU stats
		cpuValues := make([]float64, len(stats))
		memoryValues := make([]float64, len(stats))
		
		for i, sample := range stats {
			cpuValues[i] = sample.CPUUsage
			memoryValues[i] = sample.MemoryMB
		}

		summary.CPU = calculateStatsSummary(cpuValues)
		summary.Memory = calculateStatsSummary(memoryValues)

		summaries = append(summaries, summary)
	}

	// Sort by container name for consistent output
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].ContainerName < summaries[j].ContainerName
	})

	return summaries
}

// calculateStatsSummary calculates min, max, and average for a slice of values
func calculateStatsSummary(values []float64) StatsSummary {
	if len(values) == 0 {
		return StatsSummary{}
	}

	min := values[0]
	max := values[0]
	sum := 0.0

	for _, value := range values {
		if value < min {
			min = value
		}
		if value > max {
			max = value
		}
		sum += value
	}

	return StatsSummary{
		Min:     min,
		Max:     max,
		Average: sum / float64(len(values)),
	}
}

// PrintSummary prints the statistics summary to the console
func (sc *StatsCollector) PrintSummary() {
	summaries := sc.GetSummary()
	
	if len(summaries) == 0 {
		log.Printf("No container statistics collected")
		return
	}

	log.Printf("Container Resource Usage Summary:")
	log.Printf("================================")
	
	for _, summary := range summaries {
		log.Printf("Container: %s (%d samples)", summary.ContainerName, summary.SampleCount)
		log.Printf("  CPU Usage:    Min: %6.2f%%  Max: %6.2f%%  Avg: %6.2f%%", 
			summary.CPU.Min, summary.CPU.Max, summary.CPU.Average)
		log.Printf("  Memory Usage: Min: %6.1f MB Max: %6.1f MB Avg: %6.1f MB", 
			summary.Memory.Min, summary.Memory.Max, summary.Memory.Average)
		log.Printf("")
	}
}

// CheckMemoryLimits checks if any containers exceeded their memory limits
func (sc *StatsCollector) CheckMemoryLimits(hsLimitMB, tsLimitMB float64) []MemoryViolation {
	if hsLimitMB <= 0 && tsLimitMB <= 0 {
		return nil
	}

	summaries := sc.GetSummary()
	var violations []MemoryViolation

	for _, summary := range summaries {
		var limitMB float64
		if strings.HasPrefix(summary.ContainerName, "hs-") {
			limitMB = hsLimitMB
		} else if strings.HasPrefix(summary.ContainerName, "ts-") {
			limitMB = tsLimitMB
		} else {
			continue // Skip containers that don't match our patterns
		}

		if limitMB > 0 && summary.Memory.Max > limitMB {
			violations = append(violations, MemoryViolation{
				ContainerName: summary.ContainerName,
				MaxMemoryMB:   summary.Memory.Max,
				LimitMB:       limitMB,
			})
		}
	}

	return violations
}

// PrintSummaryAndCheckLimits prints the statistics summary and returns memory violations if any
func (sc *StatsCollector) PrintSummaryAndCheckLimits(hsLimitMB, tsLimitMB float64) []MemoryViolation {
	sc.PrintSummary()
	return sc.CheckMemoryLimits(hsLimitMB, tsLimitMB)
}

// Close closes the stats collector and cleans up resources
func (sc *StatsCollector) Close() error {
	sc.StopCollection()
	return sc.client.Close()
}