// Package testgen provides inputs shared by property tests.
package testgen

import (
	"unicode"

	"pgregory.net/rapid"
)

// Letter draws a Unicode letter with extra weight on several writing systems.
func Letter() *rapid.Generator[rune] {
	return rapid.RuneFrom([]rune("aÅש李𐐀"), unicode.Letter) //nolint:gosmopolitan // The examples cover different UTF-8 widths and scripts.
}
