package entraptor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/GyldendalDigital/entraptor/internal/utils"
	"github.com/google/uuid"
)

type GroupAccessChecker struct {
	allowedGroups      []uuid.UUID
	allowedNamedGroups map[string]uuid.UUID
	cacher             Cacher
	fetcher            RolesFetcher
	logger             *slog.Logger
	redirectURL        string // If set, users will be redirected here on unauthorized access
}

type GroupAccessOption func(*GroupAccessChecker)

func WithAllowedGroups(groups []uuid.UUID) GroupAccessOption {
	return func(gac *GroupAccessChecker) {
		gac.allowedGroups = groups
	}
}

func WithAllowedNamedGroups(groups map[string]uuid.UUID) GroupAccessOption {
	return func(gac *GroupAccessChecker) {
		gac.allowedNamedGroups = groups
	}
}

func WithCacher(c Cacher) GroupAccessOption {
	return func(gac *GroupAccessChecker) {
		gac.cacher = c
	}
}

func WithRedirectURL(url string) GroupAccessOption {
	return func(gac *GroupAccessChecker) {
		gac.redirectURL = url
	}
}

/*
WithRolesFetcher overrides how access tokens are resolved to app role IDs.
The default is a GraphRolesFetcher calling Microsoft Graph; tests can
substitute a StaticRolesFetcher to avoid network calls.
*/
func WithRolesFetcher(f RolesFetcher) GroupAccessOption {
	return func(gac *GroupAccessChecker) {
		gac.fetcher = f
	}
}

/*
WithLogger sets the logger used by the checker. The default discards all
output, so production callers wanting logs must pass one explicitly.
*/
func WithLogger(l *slog.Logger) GroupAccessOption {
	return func(gac *GroupAccessChecker) {
		gac.logger = l
	}
}

func NewGroupAccessChecker(options ...GroupAccessOption) *GroupAccessChecker {
	gac := &GroupAccessChecker{}
	for _, opt := range options {
		opt(gac)
	}
	if gac.cacher == nil {
		gac.cacher = DummyCacher{}
	}
	if gac.fetcher == nil {
		gac.fetcher = &GraphRolesFetcher{}
	}
	if gac.logger == nil {
		gac.logger = slog.New(slog.DiscardHandler)
	}
	return gac
}

func (gac *GroupAccessChecker) GroupAccessCheck(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gac.logger.Debug("Checking access", "method", r.Method, "path", r.URL.Path)

		roleIDs, err := gac.GetUserAppRolesFromAccessToken(w, r)
		if err != nil {
			return
		}

		allowed := make(map[uuid.UUID]struct{}, len(gac.allowedGroups))
		for _, a := range gac.allowedGroups {
			allowed[a] = struct{}{}
		}

		if !gac.anyRoleAllowed(roleIDs, allowed) {
			if gac.redirectURL != "" {
				http.Redirect(w, r, gac.redirectURL, http.StatusFound)
				return
			}
			utils.APIUnauthorized(w)
			return
		}

		next(w, r)
	}
}

func (gac *GroupAccessChecker) NamedGroupAccessCheck(roleNames []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gac.logger.Debug("Checking access", "method", r.Method, "path", r.URL.Path)

		roleIDs, err := gac.GetUserAppRolesFromAccessToken(w, r)
		if err != nil {
			return
		}

		allowed := make(map[uuid.UUID]struct{})
		for _, name := range roleNames {
			if roleUUID, ok := gac.allowedNamedGroups[name]; ok && roleUUID != uuid.Nil {
				allowed[roleUUID] = struct{}{}
			}
		}

		if !gac.anyRoleAllowed(roleIDs, allowed) {
			if gac.redirectURL != "" {
				http.Redirect(w, r, gac.redirectURL, http.StatusFound)
				return
			}
			utils.APIUnauthorized(w)
			return
		}

		next(w, r)
	}
}

func (gac *GroupAccessChecker) anyRoleAllowed(roleIDs []string, allowed map[uuid.UUID]struct{}) bool {
	for _, gid := range roleIDs {
		if uuidVal, err := uuid.Parse(gid); err == nil {
			if _, ok := allowed[uuidVal]; ok {
				return true
			}
		}
	}
	return false
}

func (gac *GroupAccessChecker) GetUserAppRoles(ctx context.Context, accessToken string) ([]string, int, error) {
	if accessToken == "" {
		gac.logger.Error("Access token is empty")
		return nil, http.StatusUnauthorized, errors.New("access token is empty")
	}
	cacheKey := gac.cacher.CacheKey(accessToken)
	if roles, found, err := gac.cacher.Get(cacheKey); err != nil {
		gac.logger.Error("Cacher get error", "error", err)
	} else if found {
		gac.logger.Debug("Cache hit for access token")
		return roles, http.StatusOK, nil
	}

	roleIDs, statusCode, err := gac.fetcher.FetchRoles(ctx, accessToken)
	if err != nil {
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			gac.logger.Info("Unauthorized access token", "status", statusCode)
			return nil, statusCode, fmt.Errorf("unauthorized access token: %w", err)
		}
		gac.logger.Error("Failed to fetch user roles", "status", statusCode, "error", err)
		return nil, statusCode, err
	}
	gac.cacher.Set(cacheKey, roleIDs)
	return roleIDs, http.StatusOK, nil
}

func (gac *GroupAccessChecker) GetUserAppRolesFromAccessToken(w http.ResponseWriter, r *http.Request) ([]string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		if gac.redirectURL != "" {
			http.Redirect(w, r, gac.redirectURL, http.StatusFound)
			return nil, errors.New("authorization header missing")
		}
		utils.APIErrorHandler(w, "Authorization header missing", http.StatusUnauthorized)
		return nil, errors.New("authorization header missing")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		utils.APIErrorHandler(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return nil, errors.New("invalid authorization header format")
	}
	token := parts[1]

	roleIDs, statusCode, err := gac.GetUserAppRoles(r.Context(), token)
	if err != nil {
		utils.APIErrorHandler(w, "Failed to get user roles", statusCode)
		return nil, err
	}
	return roleIDs, nil
}
