package servertest_test

import (
	"context"
	"net/http"
	"testing"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validPolicy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

func TestAPIv1_SetAndGetPolicy(t *testing.T) {
	_, client := apiClient(t)
	ctx := context.Background()

	setResp, err := client.SetPolicy(ctx, &apiv1.SetPolicyReq{
		Policy: apiv1.NewOptString(validPolicy),
	})
	require.NoError(t, err)
	require.NotEmpty(t, setResp.Policy.Value)

	getResp, err := client.GetPolicy(ctx)
	require.NoError(t, err)
	assert.Equal(t, setResp.Policy.Value, getResp.Policy.Value)
}

func TestAPIv1_CheckPolicy(t *testing.T) {
	_, client := apiClient(t)
	ctx := context.Background()

	require.NoError(t, client.CheckPolicy(ctx, &apiv1.CheckPolicyReq{
		Policy: apiv1.NewOptString(validPolicy),
	}))

	// Invalid policy is a 400.
	requireProblem(t, client.CheckPolicy(ctx, &apiv1.CheckPolicyReq{
		Policy: apiv1.NewOptString("{not valid"),
	}), http.StatusBadRequest)
}
