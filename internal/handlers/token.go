package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/authcode"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/config"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/keys"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/token"
)

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int64  `json:"refresh_expires_in,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

// TokenErrorResponse represents an OAuth2 error response
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// HandleToken returns a handler for the token endpoint
func HandleToken(baseURL string, cfg config.Config) http.HandlerFunc {
	issuer := baseURL + "/realms/mock"

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			writeTokenError(w, "invalid_request", "failed to parse form data")
			return
		}

		grantType := r.FormValue("grant_type")
		clientID := r.FormValue("client_id")

		// Fall back to HTTP Basic Authentication for client_id/client_secret
		// (as per RFC 6749 Section 2.3.1)
		if clientID == "" {
			if basicID, _, ok := r.BasicAuth(); ok {
				clientID = basicID
			}
		}

		log.Printf("  -> token request: grant_type=%s client_id=%s", grantType, clientID)

		switch grantType {
		case "authorization_code":
			handleAuthorizationCodeGrant(w, r, issuer, cfg)
		case "client_credentials":
			user := cfg.GetUserForClient(clientID)
			handleClientCredentialsGrant(w, r, issuer, user)
		case "refresh_token":
			user := cfg.GetUserForClient(clientID)
			handleRefreshTokenGrant(w, r, issuer, user)
		default:
			writeTokenError(w, "unsupported_grant_type", "grant_type must be authorization_code, client_credentials, or refresh_token")
		}
	}
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, issuer string, cfg config.Config) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	// code_verifier is sent but we don't validate it

	log.Printf("  -> authorization_code grant: code=%s client_id=%s redirect_uri=%s", code, clientID, redirectURI)

	// Consume the authorization code
	codeData, ok := authcode.Consume(code)
	if !ok {
		log.Printf("  -> authorization_code grant: invalid or expired code=%s", code)
		writeTokenError(w, "invalid_grant", "invalid or expired authorization code")
		return
	}

	log.Printf("  -> authorization_code grant: code consumed, user_index=%d scope=%s nonce=%s", codeData.UserIndex, codeData.Scope, codeData.Nonce)

	// Resolve user: if a user was selected during authorization, use the
	// stored index; otherwise fall back to the per-client / default user.
	var user config.User
	if codeData.UserSelected && codeData.UserIndex >= 0 && codeData.UserIndex < len(cfg.Users) {
		user = cfg.Users[codeData.UserIndex]
	} else {
		user = cfg.GetUserForClient(clientID)
	}

	// Build token request from user config
	req := buildTokenRequest(user, clientID, codeData.Scope)

	// Generate session state
	sessionState := token.GenerateSessionID()

	// Generate access token
	accessToken, err := token.Generate(req, issuer, keys.GetPrivateKey(), keys.GetKeyID())
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate access token")
		return
	}

	// Generate ID token with nonce
	idToken, err := token.GenerateIDToken(req, issuer, keys.GetPrivateKey(), keys.GetKeyID(), clientID, codeData.Nonce)
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate id token")
		return
	}

	// Generate refresh token
	refreshToken, err := token.GenerateRefreshToken(req.Sub, issuer, keys.GetPrivateKey(), keys.GetKeyID(), sessionState)
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate refresh token")
		return
	}

	writeTokenResponse(w, TokenResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        300,
		RefreshToken:     refreshToken,
		RefreshExpiresIn: 1800,
		IDToken:          idToken,
		NotBeforePolicy:  0,
		SessionState:     sessionState,
		Scope:            codeData.Scope,
	})
	log.Printf("  -> authorization_code grant: issued tokens for sub=%s (access_token=%s)", req.Sub, accessToken)
}

func handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, issuer string, user config.User) {
	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")

	log.Printf("  -> client_credentials grant: client_id=%s scope=%s user=%s", clientID, scope, user.PreferredUsername)

	// Build token request from user config
	req := buildTokenRequest(user, clientID, scope)

	// Generate access token only (no refresh token or ID token for client credentials)
	accessToken, err := token.Generate(req, issuer, keys.GetPrivateKey(), keys.GetKeyID())
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate access token")
		return
	}

	writeTokenResponse(w, TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       300,
		NotBeforePolicy: 0,
		SessionState:    token.GenerateSessionID(),
		Scope:           scope,
	})
	log.Printf("  -> client_credentials grant: issued access_token=%s", accessToken)
}

func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, issuer string, user config.User) {
	clientID := r.FormValue("client_id")
	refreshTokenValue := r.FormValue("refresh_token")
	// refresh_token is sent but we don't validate it - always return new tokens

	log.Printf("  -> refresh_token grant: client_id=%s user=%s refresh_token=%s", clientID, user.PreferredUsername, refreshTokenValue)

	scope := "openid"

	// Build token request from user config
	req := buildTokenRequest(user, clientID, scope)

	// Generate session state
	sessionState := token.GenerateSessionID()

	// Generate new access token
	accessToken, err := token.Generate(req, issuer, keys.GetPrivateKey(), keys.GetKeyID())
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate access token")
		return
	}

	// Generate new ID token (no nonce for refresh)
	idToken, err := token.GenerateIDToken(req, issuer, keys.GetPrivateKey(), keys.GetKeyID(), clientID, "")
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate id token")
		return
	}

	// Generate new refresh token
	refreshToken, err := token.GenerateRefreshToken(req.Sub, issuer, keys.GetPrivateKey(), keys.GetKeyID(), sessionState)
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate refresh token")
		return
	}

	writeTokenResponse(w, TokenResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        300,
		RefreshToken:     refreshToken,
		RefreshExpiresIn: 1800,
		IDToken:          idToken,
		NotBeforePolicy:  0,
		SessionState:     sessionState,
		Scope:            scope,
	})
	log.Printf("  -> refresh_token grant: issued new tokens for sub=%s (access_token=%s)", req.Sub, accessToken)
}

func buildTokenRequest(user config.User, clientID string, scope string) token.Request {
	return token.Request{
		Sub:               user.Sub,
		Azp:               clientID,
		Aud:               []string{clientID, "account"},
		Scope:             scope,
		EmailVerified:     user.EmailVerified,
		Name:              user.Name,
		Groups:            user.Groups,
		PreferredUsername: user.PreferredUsername,
		GivenName:         user.GivenName,
		FamilyName:        user.FamilyName,
		Email:             user.Email,
		RealmAccess:       token.RoleAccess{Roles: user.RealmAccess.Roles},
		ResourceAccess:    convertResourceAccess(user.ResourceAccess),
		ExpSeconds:        300,
	}
}

func convertResourceAccess(ra map[string]config.RoleAccess) map[string]token.RoleAccess {
	result := make(map[string]token.RoleAccess)
	for k, v := range ra {
		result[k] = token.RoleAccess{Roles: v.Roles}
	}
	return result
}

func writeTokenResponse(w http.ResponseWriter, resp TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

func writeTokenError(w http.ResponseWriter, errorCode string, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(TokenErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}
