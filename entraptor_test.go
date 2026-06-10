package entraptor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

var (
	adminRole    = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	readonlyRole = uuid.MustParse("22222222-2222-2222-2222-222222222222")
)

func staticChecker(opts ...GroupAccessOption) *GroupAccessChecker {
	base := []GroupAccessOption{
		WithRolesFetcher(StaticRolesFetcher{
			"admin-token":    {adminRole.String()},
			"readonly-token": {readonlyRole.String()},
			"norole-token":   {},
		}),
	}
	return NewGroupAccessChecker(append(base, opts...)...)
}

func doRequest(t *testing.T, handler http.HandlerFunc, authz string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("granted"))
}

func TestGroupAccessCheckWithStaticFetcher(t *testing.T) {
	t.Parallel()
	gac := staticChecker(WithAllowedGroups([]uuid.UUID{adminRole}))
	handler := gac.GroupAccessCheck(okHandler)

	cases := []struct {
		name   string
		authz  string
		status int
	}{
		{"allowed role", "Bearer admin-token", http.StatusOK},
		{"wrong role", "Bearer readonly-token", http.StatusUnauthorized},
		{"no roles", "Bearer norole-token", http.StatusUnauthorized},
		{"unknown token", "Bearer not-in-map", http.StatusUnauthorized},
		{"missing header", "", http.StatusUnauthorized},
		{"malformed header", "NotBearer admin-token", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, handler, tc.authz)
			if rec.Code != tc.status {
				t.Fatalf("status=%d want %d (body=%s)", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestNamedGroupAccessCheck(t *testing.T) {
	t.Parallel()
	gac := staticChecker(WithAllowedNamedGroups(map[string]uuid.UUID{
		"admin":    adminRole,
		"readonly": readonlyRole,
		"broken":   uuid.Nil,
	}))

	adminOnly := gac.NamedGroupAccessCheck([]string{"admin"}, okHandler)
	if rec := doRequest(t, adminOnly, "Bearer admin-token"); rec.Code != http.StatusOK {
		t.Errorf("admin via admin-only: status=%d want 200", rec.Code)
	}
	if rec := doRequest(t, adminOnly, "Bearer readonly-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("readonly via admin-only: status=%d want 401", rec.Code)
	}

	either := gac.NamedGroupAccessCheck([]string{"admin", "readonly"}, okHandler)
	if rec := doRequest(t, either, "Bearer readonly-token"); rec.Code != http.StatusOK {
		t.Errorf("readonly via either: status=%d want 200", rec.Code)
	}

	// nil-UUID and unknown names resolve to nothing
	broken := gac.NamedGroupAccessCheck([]string{"broken", "nonexistent"}, okHandler)
	if rec := doRequest(t, broken, "Bearer admin-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("broken group: status=%d want 401", rec.Code)
	}
}

func TestRedirectOnUnauthorized(t *testing.T) {
	t.Parallel()
	gac := staticChecker(
		WithAllowedGroups([]uuid.UUID{adminRole}),
		WithRedirectURL("https://login.example.test"),
	)
	handler := gac.GroupAccessCheck(okHandler)

	for _, authz := range []string{"", "Bearer readonly-token"} {
		rec := doRequest(t, handler, authz)
		if rec.Code != http.StatusFound {
			t.Errorf("authz=%q: status=%d want 302", authz, rec.Code)
			continue
		}
		if loc := rec.Header().Get("Location"); loc != "https://login.example.test" {
			t.Errorf("authz=%q: Location=%q", authz, loc)
		}
	}
}

type recordingCacher struct {
	store map[string][]string
	gets  int
	sets  int
	hits  int
}

func newRecordingCacher() *recordingCacher {
	return &recordingCacher{store: map[string][]string{}}
}

func (c *recordingCacher) Get(key string) ([]string, bool, error) {
	c.gets++
	roles, ok := c.store[key]
	if ok {
		c.hits++
	}
	return roles, ok, nil
}

func (c *recordingCacher) Set(key string, value []string) error {
	c.sets++
	c.store[key] = value
	return nil
}

func (c *recordingCacher) CacheKey(token string) string {
	return "k:" + token
}

type countingFetcher struct {
	inner RolesFetcher
	calls int
}

func (f *countingFetcher) FetchRoles(ctx context.Context, token string) ([]string, int, error) {
	f.calls++
	return f.inner.FetchRoles(ctx, token)
}

func TestCacheHitAndMiss(t *testing.T) {
	t.Parallel()
	cacher := newRecordingCacher()
	fetcher := &countingFetcher{inner: StaticRolesFetcher{"admin-token": {adminRole.String()}}}
	gac := NewGroupAccessChecker(
		WithAllowedGroups([]uuid.UUID{adminRole}),
		WithRolesFetcher(fetcher),
		WithCacher(cacher),
	)
	handler := gac.GroupAccessCheck(okHandler)

	// first request: miss → fetch → set
	if rec := doRequest(t, handler, "Bearer admin-token"); rec.Code != http.StatusOK {
		t.Fatalf("first request: status=%d", rec.Code)
	}
	if fetcher.calls != 1 || cacher.sets != 1 || cacher.hits != 0 {
		t.Fatalf("after miss: fetches=%d sets=%d hits=%d", fetcher.calls, cacher.sets, cacher.hits)
	}

	// second request: hit → no fetch
	if rec := doRequest(t, handler, "Bearer admin-token"); rec.Code != http.StatusOK {
		t.Fatalf("second request: status=%d", rec.Code)
	}
	if fetcher.calls != 1 || cacher.hits != 1 {
		t.Fatalf("after hit: fetches=%d hits=%d", fetcher.calls, cacher.hits)
	}
}

func TestStaticRolesFetcherUnknownToken(t *testing.T) {
	t.Parallel()
	f := StaticRolesFetcher{"known": {adminRole.String()}}
	_, status, err := f.FetchRoles(context.Background(), "unknown")
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("status=%d err=%v; want 401 + error", status, err)
	}
}

func TestGraphRolesFetcher(t *testing.T) {
	t.Parallel()
	var gotAuthz, gotPath string
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthz = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]string{
				{"appRoleId": adminRole.String()},
				{"appRoleId": adminRole.String()}, // duplicate must be deduped
				{"appRoleId": readonlyRole.String()},
			},
		})
	}))
	defer graph.Close()

	f := &GraphRolesFetcher{BaseURL: graph.URL}
	roles, status, err := f.FetchRoles(context.Background(), "the-token")
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if gotAuthz != "Bearer the-token" {
		t.Errorf("Authorization=%q", gotAuthz)
	}
	if gotPath != "/v1.0/me/appRoleAssignments" {
		t.Errorf("path=%q", gotPath)
	}
	if len(roles) != 2 {
		t.Errorf("roles=%v want 2 deduped entries", roles)
	}
}

func TestGraphRolesFetcherNon200(t *testing.T) {
	t.Parallel()
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer graph.Close()

	f := &GraphRolesFetcher{BaseURL: graph.URL}
	_, status, err := f.FetchRoles(context.Background(), "t")
	if err == nil || status != http.StatusForbidden {
		t.Fatalf("status=%d err=%v; want 403 + error", status, err)
	}
}

func TestGraphRolesFetcherHonoursContext(t *testing.T) {
	t.Parallel()
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer graph.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &GraphRolesFetcher{BaseURL: graph.URL}
	_, _, err := f.FetchRoles(ctx, "t")
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v; want context.Canceled", err)
	}
}

func TestEmptyAccessToken(t *testing.T) {
	t.Parallel()
	gac := staticChecker()
	_, status, err := gac.GetUserAppRoles(context.Background(), "")
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("status=%d err=%v; want 401 + error", status, err)
	}
}
