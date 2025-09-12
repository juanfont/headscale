package util

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestYesNo(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "y answer",
			input:    "y\n",
			expected: true,
		},
		{
			name:     "Y answer",
			input:    "Y\n",
			expected: true,
		},
		{
			name:     "yes answer",
			input:    "yes\n",
			expected: true,
		},
		{
			name:     "YES answer",
			input:    "YES\n",
			expected: true,
		},
		{
			name:     "sure answer",
			input:    "sure\n",
			expected: true,
		},
		{
			name:     "SURE answer",
			input:    "SURE\n",
			expected: true,
		},
		{
			name:     "n answer",
			input:    "n\n",
			expected: false,
		},
		{
			name:     "no answer",
			input:    "no\n",
			expected: false,
		},
		{
			name:     "empty answer",
			input:    "\n",
			expected: false,
		},
		{
			name:     "invalid answer",
			input:    "maybe\n",
			expected: false,
		},
		{
			name:     "random text",
			input:    "foobar\n",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdin
			oldStdin := os.Stdin
			r, w, _ := os.Pipe()
			os.Stdin = r

			// Capture stderr
			oldStderr := os.Stderr
			stderrR, stderrW, _ := os.Pipe()
			os.Stderr = stderrW

			// Write test input
			go func() {
				defer w.Close()
				w.WriteString(tt.input)
			}()

			// Call the function
			result := YesNo("Test question")

			// Restore stdin and stderr
			os.Stdin = oldStdin
			os.Stderr = oldStderr
			stderrW.Close()

			// Check the result
			if result != tt.expected {
				t.Errorf("YesNo() = %v, want %v", result, tt.expected)
			}

			// Check that the prompt was written to stderr
			var stderrBuf bytes.Buffer
			io.Copy(&stderrBuf, stderrR)
			stderrR.Close()

			expectedPrompt := "Test question [y/n] "
			actualPrompt := stderrBuf.String()
			if actualPrompt != expectedPrompt {
				t.Errorf("Expected prompt %q, got %q", expectedPrompt, actualPrompt)
			}
		})
	}
}

func TestYesNoPromptMessage(t *testing.T) {
	// Capture stdin
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	// Capture stderr
	oldStderr := os.Stderr
	stderrR, stderrW, _ := os.Pipe()
	os.Stderr = stderrW

	// Write test input
	go func() {
		defer w.Close()
		w.WriteString("n\n")
	}()

	// Call the function with a custom message
	customMessage := "Do you want to continue with this dangerous operation?"
	YesNo(customMessage)

	// Restore stdin and stderr
	os.Stdin = oldStdin
	os.Stderr = oldStderr
	stderrW.Close()

	// Check that the custom message was included in the prompt
	var stderrBuf bytes.Buffer
	io.Copy(&stderrBuf, stderrR)
	stderrR.Close()

	expectedPrompt := customMessage + " [y/n] "
	actualPrompt := stderrBuf.String()
	if actualPrompt != expectedPrompt {
		t.Errorf("Expected prompt %q, got %q", expectedPrompt, actualPrompt)
	}
}

func TestYesNoCaseInsensitive(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{"Yes\n", true},
		{"YES\n", true},
		{"yEs\n", true},
		{"sure\n", true},
		{"Sure\n", true},
		{"SURE\n", true},
		{"SuRe\n", true},
	}

	for _, tc := range testCases {
		t.Run("input_"+strings.TrimSpace(tc.input), func(t *testing.T) {
			// Capture stdin
			oldStdin := os.Stdin
			r, w, _ := os.Pipe()
			os.Stdin = r

			// Capture stderr to avoid output during tests
			oldStderr := os.Stderr
			stderrR, stderrW, _ := os.Pipe()
			os.Stderr = stderrW

			// Write test input
			go func() {
				defer w.Close()
				w.WriteString(tc.input)
			}()

			// Call the function
			result := YesNo("Test")

			// Restore stdin and stderr
			os.Stdin = oldStdin
			os.Stderr = oldStderr
			stderrW.Close()

			// Drain stderr
			io.Copy(io.Discard, stderrR)
			stderrR.Close()

			if result != tc.expected {
				t.Errorf("Input %q: expected %v, got %v", strings.TrimSpace(tc.input), tc.expected, result)
			}
		})
	}
}
