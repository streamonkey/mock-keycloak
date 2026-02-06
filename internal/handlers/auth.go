package handlers

import (
	"net/http"
	"net/url"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/authcode"
)

// HandleAuth returns a handler for the authorization endpoint
// Supports PKCE flow as used by keycloak-js
func HandleAuth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		// Extract parameters from the authorization request
		clientID := query.Get("client_id")
		redirectURI := query.Get("redirect_uri")
		state := query.Get("state")
		responseMode := query.Get("response_mode")
		responseType := query.Get("response_type")
		scope := query.Get("scope")
		nonce := query.Get("nonce")
		// code_challenge and code_challenge_method are sent but we don't validate them

		// Validate required parameters
		if responseType != "code" {
			http.Error(w, "unsupported_response_type", http.StatusBadRequest)
			return
		}

		if redirectURI == "" {
			http.Error(w, "missing redirect_uri", http.StatusBadRequest)
			return
		}

		// Default response mode to fragment (as keycloak-js uses)
		if responseMode == "" {
			responseMode = "fragment"
		}

		// Generate authorization code and store metadata
		code := authcode.Generate(authcode.AuthCodeData{
			ClientID:     clientID,
			RedirectURI:  redirectURI,
			Nonce:        nonce,
			Scope:        scope,
			ResponseMode: responseMode,
		})

		// Build redirect URL
		redirectURL, err := url.Parse(redirectURI)
		if err != nil {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}

		// Build response parameters
		params := url.Values{}
		params.Set("code", code)
		if state != "" {
			params.Set("state", state)
		}

		// Apply parameters based on response_mode
		if responseMode == "fragment" {
			redirectURL.Fragment = params.Encode()
		} else {
			// query mode
			redirectURL.RawQuery = params.Encode()
		}

		// Redirect to the client
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	}
}
