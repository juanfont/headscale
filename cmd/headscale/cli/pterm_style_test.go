package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestColourTime(t *testing.T) {
	tests := []struct {
		name         string
		date         time.Time
		expectedText string
		expectRed    bool
		expectGreen  bool
	}{
		{
			name:         "future date should be green",
			date:         time.Now().Add(1 * time.Hour),
			expectedText: time.Now().Add(1 * time.Hour).Format("2006-01-02 15:04:05"),
			expectGreen:  true,
			expectRed:    false,
		},
		{
			name:         "past date should be red",
			date:         time.Now().Add(-1 * time.Hour),
			expectedText: time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04:05"),
			expectGreen:  false,
			expectRed:    true,
		},
		{
			name:         "very old date should be red",
			date:         time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC),
			expectedText: "2020-01-01 12:00:00",
			expectGreen:  false,
			expectRed:    true,
		},
		{
			name:         "far future date should be green",
			date:         time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC),
			expectedText: "2030-12-31 23:59:59",
			expectGreen:  true,
			expectRed:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ColourTime(tt.date)
			
			// Check that the formatted time string is present
			assert.Contains(t, result, tt.expectedText)
			
			// Check for color codes based on expectation
			if tt.expectGreen {
				// pterm.LightGreen adds color codes, check for green color escape sequences
				assert.Contains(t, result, "\033[92m", "Expected green color codes")
			}
			
			if tt.expectRed {
				// pterm.LightRed adds color codes, check for red color escape sequences
				assert.Contains(t, result, "\033[91m", "Expected red color codes")
			}
		})
	}
}

func TestColourTimeFormatting(t *testing.T) {
	// Test that the date format is correct
	testDate := time.Date(2023, 6, 15, 14, 30, 45, 0, time.UTC)
	result := ColourTime(testDate)
	
	// Should contain the correctly formatted date
	assert.Contains(t, result, "2023-06-15 14:30:45")
}

func TestColourTimeWithTimezones(t *testing.T) {
	// Test with different timezones
	utc := time.Now().UTC()
	local := utc.In(time.Local)
	
	resultUTC := ColourTime(utc)
	resultLocal := ColourTime(local)
	
	// Both should format to the same time (since it's the same instant)
	// but may have different colors depending on when "now" is
	utcFormatted := utc.Format("2006-01-02 15:04:05")
	localFormatted := local.Format("2006-01-02 15:04:05")
	
	assert.Contains(t, resultUTC, utcFormatted)
	assert.Contains(t, resultLocal, localFormatted)
}

func TestColourTimeEdgeCases(t *testing.T) {
	// Test with zero time
	zeroTime := time.Time{}
	result := ColourTime(zeroTime)
	assert.Contains(t, result, "0001-01-01 00:00:00")
	
	// Zero time is definitely in the past, so should be red
	assert.Contains(t, result, "\033[91m", "Zero time should be red")
}

func TestColourTimeConsistency(t *testing.T) {
	// Test that calling the function multiple times with the same input
	// produces consistent results (within a reasonable time window)
	testDate := time.Now().Add(-5 * time.Minute) // 5 minutes ago
	
	result1 := ColourTime(testDate)
	time.Sleep(10 * time.Millisecond) // Small delay
	result2 := ColourTime(testDate)
	
	// Results should be identical since the input date hasn't changed
	// and it's still in the past relative to "now"
	assert.Equal(t, result1, result2)
}

func TestColourTimeNearCurrentTime(t *testing.T) {
	// Test dates very close to current time
	now := time.Now()
	
	// 1 second in the past
	pastResult := ColourTime(now.Add(-1 * time.Second))
	assert.Contains(t, pastResult, "\033[91m", "1 second ago should be red")
	
	// 1 second in the future
	futureResult := ColourTime(now.Add(1 * time.Second))
	assert.Contains(t, futureResult, "\033[92m", "1 second in future should be green")
}

func TestColourTimeStringContainsNoUnexpectedCharacters(t *testing.T) {
	// Test that the result doesn't contain unexpected characters
	testDate := time.Now()
	result := ColourTime(testDate)
	
	// Should not contain newlines or other unexpected characters
	assert.False(t, strings.Contains(result, "\n"), "Result should not contain newlines")
	assert.False(t, strings.Contains(result, "\r"), "Result should not contain carriage returns")
	
	// Should contain the expected format
	dateStr := testDate.Format("2006-01-02 15:04:05")
	assert.Contains(t, result, dateStr)
}