package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/keys"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/token"
)

// OpenIDConfiguration represents the OpenID Connect discovery document
type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	CheckSessionIframe                string   `json:"check_session_iframe"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// HandleOpenIDConfig returns a handler for the OpenID Connect discovery endpoint
func HandleOpenIDConfig(baseURL string) http.HandlerFunc {
	realmURL := baseURL + "/realms/mock"

	config := OpenIDConfiguration{
		Issuer:                            realmURL,
		AuthorizationEndpoint:             realmURL + "/protocol/openid-connect/auth",
		TokenEndpoint:                     realmURL + "/protocol/openid-connect/token",
		EndSessionEndpoint:                realmURL + "/protocol/openid-connect/logout",
		JwksURI:                           realmURL + "/protocol/openid-connect/certs",
		CheckSessionIframe:                realmURL + "/protocol/openid-connect/login-status-iframe.html",
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query", "fragment"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("  -> serving OpenID configuration (issuer=%s)", realmURL)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	}
}

// HandleJWKS returns a handler for the JWKS endpoint
func HandleJWKS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("  -> serving JWKS (key_id=%s)", keys.GetKeyID())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys.GetJWKS())
	}
}

// HandleLoginStatusIframe returns a handler that serves the login status iframe
func HandleLoginStatusIframe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginStatusIframeHTML))
	}
}

// HandleIframeInit returns a handler for the iframe init endpoint
func HandleIframeInit() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("  -> iframe init (204 No Content)")
		// Always return 204 No Content to indicate the client is allowed
		w.WriteHeader(http.StatusNoContent)
	}
}

// Handle3pCookiesStep1 returns a handler for the 3rd-party cookie check step 1
func Handle3pCookiesStep1() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(thirdPartyCookiesIframeHTML))
	}
}

// Handle3pCookiesStep2 returns a handler for the 3rd-party cookie check step 2
func Handle3pCookiesStep2() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(thirdPartyCookiesIframeHTML))
	}
}

// HandleLogout returns a handler for the logout/end session endpoint
func HandleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
		log.Printf("  -> logout request (post_logout_redirect_uri=%s)", redirectURI)

		// Clear the session cookie so the next auth request requires re-login.
		clearSessionCookie(w)

		if redirectURI == "" {
			// If no redirect URI, just return 200 OK
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Logged out successfully"))
			return
		}

		// Redirect to the post_logout_redirect_uri
		http.Redirect(w, r, redirectURI, http.StatusFound)
	}
}

// HandleGetToken returns a handler for the mock token generation endpoint
func HandleGetToken(baseURL string) http.HandlerFunc {
	issuer := baseURL + "/realms/mock"

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req token.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("  -> get-signed-mock-token: invalid request body: %v", err)
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("  -> get-signed-mock-token: sub=%s azp=%s scope=%s", req.Sub, req.Azp, req.Scope)

		tokenString, err := token.Generate(req, issuer, keys.GetPrivateKey(), keys.GetKeyID())
		if err != nil {
			log.Printf("  -> get-signed-mock-token: failed to generate token: %v", err)
			http.Error(w, "failed to generate token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("  -> get-signed-mock-token: generated token (%d chars)", len(tokenString))

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(tokenString))
	}
}
