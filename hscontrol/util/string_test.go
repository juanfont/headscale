package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomStringDNSSafe(t *testing.T) {
	for i := 0; i < 100000; i++ {
		str, err := GenerateRandomStringDNSSafe(8)
		assert.Nil(t, err)
		assert.Len(t, str, 8)
	}
}
