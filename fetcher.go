package entraptor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

/*
RolesFetcher resolves an access token to the app role IDs assigned to its
user. The production implementation is GraphRolesFetcher; tests can plug
in StaticRolesFetcher to avoid calling Microsoft Graph.
*/
type RolesFetcher interface {
	FetchRoles(ctx context.Context, accessToken string) ([]string, int, error)
}

const defaultGraphBaseURL = "https://graph.microsoft.com"

/*
GraphRolesFetcher fetches app role assignments from Microsoft Graph
(/v1.0/me/appRoleAssignments). The zero value is ready to use: a 10 second
timeout client against the public Graph endpoint.
*/
type GraphRolesFetcher struct {
	HTTPClient *http.Client // default: client with a 10s timeout
	BaseURL    string       // default: "https://graph.microsoft.com"
}

func (g *GraphRolesFetcher) FetchRoles(ctx context.Context, accessToken string) ([]string, int, error) {
	client := g.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	baseURL := g.BaseURL
	if baseURL == "" {
		baseURL = defaultGraphBaseURL
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		baseURL+"/v1.0/me/appRoleAssignments?$select=appRoleId,principalDisplayName,resourceDisplayName",
		nil,
	)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("graph api returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var g2 struct {
		Value []struct{ AppRoleID string } `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&g2); err != nil {
		return nil, http.StatusInternalServerError, err
	}

	roleSet := make(map[string]struct{}, len(g2.Value))
	for _, v := range g2.Value {
		roleSet[v.AppRoleID] = struct{}{}
	}

	roleIDs := make([]string, 0, len(roleSet))
	for id := range roleSet {
		roleIDs = append(roleIDs, id)
	}
	return roleIDs, http.StatusOK, nil
}

/*
StaticRolesFetcher maps bearer tokens directly to role IDs without any
network call. Intended for tests: requests carrying a token present in the
map flow through the real middleware logic with the mapped roles; unknown
tokens are rejected with 401.
*/
type StaticRolesFetcher map[string][]string

func (s StaticRolesFetcher) FetchRoles(_ context.Context, accessToken string) ([]string, int, error) {
	if roles, ok := s[accessToken]; ok {
		return roles, http.StatusOK, nil
	}
	return nil, http.StatusUnauthorized, errors.New("unknown test token")
}
