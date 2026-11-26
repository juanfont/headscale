package command

import (
	"bytes"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Diagnostic output must preserve ordinary text and mask synthetic credentials across writes.
//
// Bound: the writer never fails, so a dropped write error passes.
func TestRapidMaskingWrites(t *testing.T) {
	t.Parallel()

	kinds := rapid.SampledFrom(
		[]string{"auth", "api", "authreq", "client", "oauthtok", "reg"},
	)

	rapid.Check(t, func(rt *rapid.T) {
		var source, want strings.Builder
		for _, kind := range rapid.SliceOfN(kinds, 1, 5).Draw(rt, "credential kinds") {
			source.WriteString("résultat [hskey-" + kind + "-exampleonly]")
			want.WriteString("résultat [hskey-" + kind + "-***]")
		}

		var out bytes.Buffer

		writer := &masking{w: &out, cred: testCred()}

		for data := []byte(source.String()); len(data) != 0; {
			size := rapid.IntRange(1, len(data)).Draw(rt, "write size")

			n, err := writer.Write(data[:size])
			if err != nil || n != size {
				rt.Fatal("masking writer rejected diagnostic input")
			}

			if !strings.HasPrefix(want.String(), out.String()) {
				rt.Fatal("published diagnostic differs from the redacted prefix")
			}

			data = data[size:]
		}

		err := writer.Flush()
		if err != nil || out.String() != want.String() {
			rt.Fatal("final diagnostic differs from the redacted message")
		}
	})
}
