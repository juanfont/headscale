package hscontrol

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/context"
)

const (
	googleOIDCIssuer              = "https://accounts.google.com"
	googleIAMDirectGroupsEndpoint = "https://content-cloudidentity.googleapis.com/v1/groups/-/memberships:searchDirectGroups"
	googleIAMScope                = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"
)

type httpGetResponse struct {
	Body    []byte
	Headers http.Header
}

func httpGet(ctx context.Context, client *http.Client, url string, authToken string) (*httpGetResponse, error) {
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if errReq != nil {
		return nil, errReq
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
	req.Header.Set("Content-Type", "application/json")

	r, errDo := client.Do(req)
	if errDo != nil {
		return nil, errDo
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Debug().
				Err(err).
				Caller().
				Msgf("Failed to close response body: %s", err.Error())
		}
	}()

	body, errRead := io.ReadAll(r.Body)
	if errRead != nil {
		return nil, errRead
	}

	response := &httpGetResponse{body, r.Header}

	if r.StatusCode >= http.StatusMultipleChoices {
		err := fmt.Errorf("status code %d: %s", r.StatusCode, string(response.Body))
		log.Warn().
			Err(err).
			Caller().
			Msgf("unsuccessful response : %s", err.Error())

		return nil, err
	}

	return response, nil
}

type googleMembershipResp struct {
	Memberships []struct {
		Membership string `json:"membership"`
		Roles      []struct {
			Name string `json:"name"`
		} `json:"roles"`
		Group    string `json:"group"`
		GroupKey struct {
			ID string `json:"id"`
		} `json:"groupKey"`
		DisplayName string            `json:"displayName"`
		Labels      map[string]string `json:"labels"`
		Description string            `json:"description,omitempty"`
	} `json:"memberships"`
	NextPageToken string `json:"nextPageToken"`
}

// API documentation : https://cloud.google.com/identity/docs/reference/rest/v1/groups.memberships/searchDirectGroups

func oidcGWorkspaceGetUserGroups(authToken, userEmail string) ([]string, error) {
	log.Debug().
		Caller().
		Msg("Retrieving groups")

	client := &http.Client{}
	ctx := context.Background()

	groups := []string{}

	endpoint := googleIAMDirectGroupsEndpoint

	url := fmt.Sprintf("%s?query=member_key_id=='%s'", endpoint, userEmail)
	nextPageToken := ""
	for page, errPage := oidcGWorkspaceRetrieveGroupsPage(ctx, client, url, nextPageToken, authToken); ; page, errPage = oidcGWorkspaceRetrieveGroupsPage(ctx, client, url, nextPageToken, authToken) {
		if errPage != nil {
			return nil, errPage
		}

		for _, group := range page.Memberships {
			groups = append(groups, group.GroupKey.ID)
		}

		nextPageToken = page.NextPageToken
		if nextPageToken == "" {
			break
		}
	}

	return groups, nil
}

func oidcGWorkspaceRetrieveGroupsPage(ctx context.Context, client *http.Client, url, nextPageToken string, authToken string) (*googleMembershipResp, error) {
	if nextPageToken != "" {
		url = fmt.Sprintf("%s&pageToken=%s", url, nextPageToken)
	}

	log.Debug().
		Caller().
		Msgf("Retrieving groups : %s", url)

	resp, err := httpGet(ctx, client, url, authToken)
	if err != nil {
		return nil, fmt.Errorf("error getting groups: %s", err)
	}

	var data googleMembershipResp
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return nil, fmt.Errorf("error unmarshalling groups: %s", err)
	}

	return &data, nil
}
