package cli

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetUserRequestFromFlags pins the distinction the whole command rests on:
// a flag that was never passed leaves the field alone (nil), while a flag passed
// with an empty value clears it (pointer to ""). An empty-string check alone
// cannot express that.
func TestSetUserRequestFromFlags(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantErr         error
		wantDisplayName *string
		wantEmail       *string
		wantPictureURL  *string
	}{
		{
			name:    "no flags is an error",
			args:    nil,
			wantErr: errNoUserFieldsToSet,
		},
		{
			name:            "display name only",
			args:            []string{"--display-name", "Vika"},
			wantDisplayName: new("Vika"),
		},
		{
			name:            "empty flag clears the field",
			args:            []string{"--picture-url", ""},
			wantPictureURL:  new(""),
			wantDisplayName: nil,
		},
		{
			name:            "all three",
			args:            []string{"--display-name", "Vika", "--email", "v@example.com", "--picture-url", "https://example.com/v.png"},
			wantDisplayName: new("Vika"),
			wantEmail:       new("v@example.com"),
			wantPictureURL:  new("https://example.com/v.png"),
		},
		{
			// Caught before the round trip so the operator gets an immediate
			// error rather than a 400.
			name:    "invalid picture url",
			args:    []string{"--picture-url", "not-a-url"},
			wantErr: types.ErrInvalidProfilePicURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "set"}
			cmd.Flags().StringP("display-name", "d", "", "")
			cmd.Flags().StringP("email", "e", "", "")
			cmd.Flags().StringP("picture-url", "p", "", "")
			require.NoError(t, cmd.Flags().Parse(tt.args))

			got, err := setUserRequestFromFlags(cmd)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantDisplayName, got.DisplayName)
			assert.Equal(t, tt.wantEmail, got.Email)
			assert.Equal(t, tt.wantPictureURL, got.PictureUrl)
		})
	}
}
