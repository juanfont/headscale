package types

import (
	"testing"
)

func TestDefaultBatcherWorkersFor(t *testing.T) {
	tests := []struct {
		cpuCount int
		expected int
	}{
		{1, 1},   // (1*3)/4 = 0, should be minimum 1
		{2, 1},   // (2*3)/4 = 1
		{4, 3},   // (4*3)/4 = 3
		{8, 6},   // (8*3)/4 = 6
		{12, 9},  // (12*3)/4 = 9
		{16, 12}, // (16*3)/4 = 12
		{20, 15}, // (20*3)/4 = 15
		{24, 18}, // (24*3)/4 = 18
	}

	for _, test := range tests {
		result := DefaultBatcherWorkersFor(test.cpuCount)
		if result != test.expected {
			t.Errorf("DefaultBatcherWorkersFor(%d) = %d, expected %d", test.cpuCount, result, test.expected)
		}
	}
}

func TestDefaultBatcherWorkers(t *testing.T) {
	// Just verify it returns a valid value (>= 1)
	result := DefaultBatcherWorkers()
	if result < 1 {
		t.Errorf("DefaultBatcherWorkers() = %d, expected value >= 1", result)
	}
}
