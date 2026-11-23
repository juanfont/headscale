package util

import (
	"errors"
	"strconv"
	"testing"

	"github.com/juanfont/headscale/internal/testgen"
	"pgregory.net/rapid"
)

func TestRapidUsernameLetters(t *testing.T) {
	letter := testgen.Letter()

	for _, size := range []int{1, 2, 4} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				runes := rapid.SliceOfN(letter, size, size).Draw(rt, "letters")
				name := string(runes)

				err := ValidateUsername(name)
				if size == 1 {
					if !errors.Is(err, ErrUsernameTooShort) {
						rt.Fatalf("single letter %q: %v", name, err)
					}
				} else if err != nil {
					rt.Fatalf("valid %d-letter name %q: %v", size, name, err)
				}
			})
		})
	}
}
