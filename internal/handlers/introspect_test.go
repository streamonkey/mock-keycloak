package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/handlers"
)

func TestIntrospect(t *testing.T) {
	tokens := mintTestTokens(t)
	handler := handlers.HandleIntrospect(testBaseURL, testRealm)
	const target = "/realms/" + testRealm + "/protocol/openid-connect/token/introspect"
	const inactive = `{"active":false}`

	// The introspecting client is deliberately not the token's azp, so the
	// test shows that client_id reports who the token was issued to.
	accessExtra := map[string]any{"active": true, "client_id": testUser.Azp, "username": testUser.PreferredUsername, "token_type": "Bearer"}

	tests := []struct {
		name       string
		method     string
		form       url.Values
		basicAuth  string // client_id sent via HTTP Basic
		wantStatus int
		wantBody   string         // the exact body, when set
		wantError  string         // "error" of a 400 body
		token      string         // for an active response: every claim of this token must be in it
		wantExtra  map[string]any // for an active response: the fields added on top of the claims, and no others
	}{
		{
			name:       "access token, client in form",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.access}, "client_id": {"resource-server"}, "client_secret": {"anything"}},
			wantStatus: http.StatusOK,
			token:      tokens.access,
			wantExtra:  accessExtra,
		},
		{
			name:       "access token, client via HTTP Basic",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.access}},
			basicAuth:  "resource-server",
			wantStatus: http.StatusOK,
			token:      tokens.access,
			wantExtra:  accessExtra,
		},
		{
			name:       "access token, no client authentication",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.access}},
			wantStatus: http.StatusOK,
			token:      tokens.access,
			wantExtra:  accessExtra,
		},
		{
			name:       "token_type_hint is ignored",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.access}, "token_type_hint": {"refresh_token"}},
			wantStatus: http.StatusOK,
			token:      tokens.access,
			wantExtra:  accessExtra,
		},
		{
			name:       "refresh token",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.refresh}},
			wantStatus: http.StatusOK,
			token:      tokens.refresh,
			wantExtra:  map[string]any{"active": true, "token_type": "Refresh"},
		},
		{
			name:       "ID token",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.id}},
			wantStatus: http.StatusOK,
			token:      tokens.id,
			wantExtra:  map[string]any{"active": true, "client_id": testUser.Azp, "username": testUser.PreferredUsername, "token_type": "ID"},
		},
		{
			name:       "expired",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.expired}},
			wantStatus: http.StatusOK,
			wantBody:   inactive,
		},
		{
			name:       "signed by a foreign key",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.foreign}},
			wantStatus: http.StatusOK,
			wantBody:   inactive,
		},
		{
			name:       "signed with RS512",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.rs512}},
			wantStatus: http.StatusOK,
			wantBody:   inactive,
		},
		{
			name:       "wrong issuer",
			method:     http.MethodPost,
			form:       url.Values{"token": {tokens.wrongIssuer}},
			wantStatus: http.StatusOK,
			wantBody:   inactive,
		},
		{
			name:       "garbage",
			method:     http.MethodPost,
			form:       url.Values{"token": {"not-a-jwt"}},
			wantStatus: http.StatusOK,
			wantBody:   inactive,
		},
		{
			name:       "missing token",
			method:     http.MethodPost,
			form:       url.Values{"client_id": {"resource-server"}},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "GET",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(tc.method, target, tc.form)
			if tc.basicAuth != "" {
				req.SetBasicAuth(tc.basicAuth, "any-secret")
			}
			rec := httptest.NewRecorder()
			handler(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}

			switch {
			case tc.wantStatus == http.StatusMethodNotAllowed:
				if got := rec.Header().Get("Allow"); got != "POST" {
					t.Errorf("Allow = %q, want %q", got, "POST")
				}

			case tc.wantBody != "":
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				if got := strings.TrimSpace(rec.Body.String()); got != tc.wantBody {
					t.Errorf("body = %s, want exactly %s", got, tc.wantBody)
				}

			case tc.wantError != "":
				var got handlers.TokenErrorResponse
				decodeJSON(t, rec, &got)
				if got.Error != tc.wantError {
					t.Errorf("error = %q, want %q", got.Error, tc.wantError)
				}

			case tc.token != "":
				var got map[string]any
				decodeJSON(t, rec, &got)
				claims := jwt.MapClaims{}
				if _, _, err := jwt.NewParser().ParseUnverified(tc.token, claims); err != nil {
					t.Fatalf("decoding test token: %v", err)
				}
				for k, want := range claims {
					if !reflect.DeepEqual(got[k], want) {
						t.Errorf("claim %s = %v, want %v", k, got[k], want)
					}
				}
				for k, want := range tc.wantExtra {
					if !reflect.DeepEqual(got[k], want) {
						t.Errorf("%s = %v, want %v", k, got[k], want)
					}
				}
				for k := range got {
					_, isClaim := claims[k]
					_, isExtra := tc.wantExtra[k]
					if !isClaim && !isExtra {
						t.Errorf("unexpected field %s = %v", k, got[k])
					}
				}
			}
		})
	}
}
