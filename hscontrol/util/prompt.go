package util

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// YesNo takes a question and prompts the user to answer the
// question with a yes or no. It appends a [y/n] to the message.
// The question is written to stderr so that content can be redirected
// without interfering with the prompt.
func YesNo(msg string) bool {
	fmt.Fprint(os.Stderr, msg+" [y/n] ")

	var resp string

	_, _ = fmt.Scanln(&resp)

	resp = strings.ToLower(resp)

	return slices.Contains([]string{"y", "yes", "sure"}, resp)
}
