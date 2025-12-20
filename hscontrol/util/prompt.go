package util

import (
	"fmt"
	"os"
	"strings"
)

// YesNo takes a question and prompts the user to answer the
// question with a yes or no. It appends a [y/n] to the message.
// The question is written to stderr so that content can be redirected
// without interfering with the prompt.
func YesNo(msg string) bool {
	fmt.Fprint(os.Stderr, msg+" [y/n] ")

	var resp string
	fmt.Scanln(&resp)
	resp = strings.ToLower(resp)
	switch resp {
	case "y", "yes", "sure":
		return true
	}
	return false
}
