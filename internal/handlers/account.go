package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/config"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/keys"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/token"
)

// accountResponse represents the Keycloak Account REST API response
type accountResponse struct {
	ID            string            `json:"id"`
	Username      string            `json:"username"`
	FirstName     string            `json:"firstName,omitempty"`
	LastName      string            `json:"lastName,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified bool              `json:"emailVerified"`
	Attributes    map[string]string `json:"attributes"`
}

// HandleAccount returns user profile info for the authenticated user.
// This implements the Keycloak Account REST API endpoint: GET /realms/{realm}/account
func HandleAccount(baseURL string, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Bearer token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			log.Printf("  -> 401 Unauthorized (missing or invalid Authorization header)")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := authHeader[len("bearer "):]

		// Parse and verify the JWT
		claims := &token.KeycloakClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return keys.GetPublicKey(), nil
		})
		if err != nil {
			log.Printf("  -> 401 Unauthorized (invalid token: %v)", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Find the matching user by sub claim
		var user *config.User
		for i := range cfg.Users {
			if cfg.Users[i].Sub == claims.Subject {
				user = &cfg.Users[i]
				break
			}
		}
		if user == nil {
			// Fall back to first user (consistent with mock behavior)
			if len(cfg.Users) > 0 {
				user = &cfg.Users[0]
			} else {
				log.Printf("  -> 404 Not Found (no users configured)")
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
		}

		resp := accountResponse{
			ID:            user.Sub,
			Username:      user.PreferredUsername,
			FirstName:     user.GivenName,
			LastName:      user.FamilyName,
			Email:         user.Email,
			EmailVerified: user.EmailVerified,
			Attributes:    map[string]string{},
		}

		w.Header().Set("Content-Type", "application/json")
		log.Printf("  -> 200 OK (account for %s)", user.PreferredUsername)
		json.NewEncoder(w).Encode(resp)
	}
}
