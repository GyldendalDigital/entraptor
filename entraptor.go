package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/GyldendalDigital/entraptor/internal/utils"
	"github.com/google/uuid"
)

func GroupAccessCheck(next http.HandlerFunc, allowedGroups []uuid.UUID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Checking access for", r.Method, r.URL.Path)

		roleIDs, err := GetUserAppRolesFromAccessToken(w, r)
		if err != nil {
			return
		}

		allowed := make(map[uuid.UUID]struct{}, len(allowedGroups))
		for _, a := range allowedGroups {
			allowed[a] = struct{}{}
		}

		authorized := false
		for _, gid := range roleIDs {
			if uuidVal, err := uuid.Parse(gid); err == nil {
				if _, ok := allowed[uuidVal]; ok {
					authorized = true
					break
				}
			}
		}

		if !authorized {
			utils.APIUnauthorized(w)
			return
		}

		next(w, r)
	}
}

func GetUserAppRoles(accessToken string) ([]string, int, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(
		"GET",
		"https://graph.microsoft.com/v1.0/me/appRoleAssignments?$select=appRoleId,principalDisplayName,resourceDisplayName",
		nil,
	)
	if err != nil {
		slog.Error("Failed to create Graph API request", "error", err)
		return nil, http.StatusInternalServerError, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Graph API request failed", "error", err)
		return nil, http.StatusInternalServerError, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Graph API returned non-200 status", "status", resp.Status)
		return nil, resp.StatusCode, fmt.Errorf("graph api returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var g struct {
		Value []struct{ AppRoleID string } `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
		return nil, http.StatusInternalServerError, err
	}

	roleSet := make(map[string]struct{}, len(g.Value))
	for _, v := range g.Value {
		roleSet[v.AppRoleID] = struct{}{}
	}

	roleIDs := make([]string, 0, len(roleSet))
	for id := range roleSet {
		roleIDs = append(roleIDs, id)
	}
	return roleIDs, http.StatusOK, nil
}

func GetUserAppRolesFromAccessToken(w http.ResponseWriter, r *http.Request) ([]string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		utils.APIErrorHandler(w, "Authorization header missing", http.StatusUnauthorized)
		return nil, errors.New("authorization header missing")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		utils.APIErrorHandler(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return nil, errors.New("invalid authorization header format")
	}
	token := parts[1]

	roleIDs, statusCode, err := GetUserAppRoles(token)
	if err != nil {
		utils.APIErrorHandler(w, "Failed to get user roles from Graph API", statusCode)
		return nil, err
	}
	return roleIDs, nil
}
