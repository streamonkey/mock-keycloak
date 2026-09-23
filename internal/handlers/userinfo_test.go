package handlers_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/handlers"
)

func TestUserInfo(t *testing.T) {
	tokens := mintTestTokens(t)
	handler := handlers.HandleUserInfo(testBaseURL, testRealm)
	const target = "/realms/" + testRealm + "/protocol/openid-connect/userinfo"
	const invalidTokenChallenge = `Bearer realm="streamonkey", error="invalid_token", error_description="`

	fullProfile := map[string]any{
		"sub":                testUser.Sub,
		"name":               testUser.Name,
		"preferred_username": testUser.PreferredUsername,
		"given_name":         testUser.GivenName,
		"family_name":        testUser.FamilyName,
		"email":              testUser.Email,
		"email_verified":     true,
	}

	tests := []struct {
		name          string
		method        string
		query         string
		authorization string
		form          url.Values
		wantStatus    int
		wantProfile   map[string]any // the whole 200 body
		wantError     string         // "error" of the 401/403 body
		wantReason    string         // part of error_description, for invalid_token
	}{
		{
			name:          "GET with Authorization header",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.access,
			wantStatus:    http.StatusOK,
			wantProfile:   fullProfile,
		},
		{
			name:          "scheme is case-insensitive",
			method:        http.MethodGet,
			authorization: "bEaReR " + tokens.access,
			wantStatus:    http.StatusOK,
			wantProfile:   fullProfile,
		},
		{
			name:        "POST with access_token form parameter",
			method:      http.MethodPost,
			form:        url.Values{"access_token": {tokens.access}},
			wantStatus:  http.StatusOK,
			wantProfile: fullProfile,
		},
		{
			name:          "empty profile claims are omitted",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.minimal,
			wantStatus:    http.StatusOK,
			wantProfile:   map[string]any{"sub": "minted-only", "email_verified": false},
		},
		{
			name:          "expired",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.expired,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    "token is expired",
		},
		{
			name:          "signed by a foreign key",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.foreign,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    "signature is invalid",
		},
		{
			name:          "signed with RS512",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.rs512,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    "signing method RS512 is invalid",
		},
		{
			name:          "wrong issuer",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.wrongIssuer,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    "invalid issuer",
		},
		{
			name:          "ID token is not an access token",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.id,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    "typ=ID",
		},
		{
			name:          "refresh token is not an access token",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.refresh,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    "typ=Refresh",
		},
		{
			name:          "garbage",
			method:        http.MethodGet,
			authorization: "Bearer not-a-jwt",
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    "malformed",
		},
		{
			// The jwt error quotes the offending character, which the
			// challenge's quoted-string must not carry through raw.
			name:          "error message containing a double quote",
			method:        http.MethodGet,
			authorization: "Bearer " + base64.RawURLEncoding.EncodeToString([]byte(`{"alg" "RS256"}`)) + ".e30.c2ln",
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    `invalid character '"' after object key`,
		},
		{
			name:          "token without sub",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.noSub,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
			wantReason:    "token has no sub",
		},
		{
			name:          "scope without openid",
			method:        http.MethodGet,
			authorization: "Bearer " + tokens.noOpenID,
			wantStatus:    http.StatusForbidden,
			wantError:     "insufficient_scope",
		},
		{
			name:       "missing token",
			method:     http.MethodGet,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_request",
		},
		{
			name:          "Basic credentials count as no token",
			method:        http.MethodGet,
			authorization: "Basic dXNlcjpwYXNz",
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_request",
		},
		{
			name:       "access_token query parameter is not read",
			method:     http.MethodGet,
			query:      "?access_token=" + tokens.access,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_request",
		},
		{
			name:          "wrong method",
			method:        http.MethodPut,
			authorization: "Bearer " + tokens.access,
			wantStatus:    http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(tc.method, target+tc.query, tc.form)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			rec := httptest.NewRecorder()
			handler(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}

			switch tc.wantStatus {
			case http.StatusOK:
				var got map[string]any
				decodeJSON(t, rec, &got)
				if !reflect.DeepEqual(got, tc.wantProfile) {
					t.Errorf("body = %v, want %v", got, tc.wantProfile)
				}

			case http.StatusMethodNotAllowed:
				if got := rec.Header().Get("Allow"); got != "GET, POST" {
					t.Errorf("Allow = %q, want %q", got, "GET, POST")
				}

			case http.StatusUnauthorized, http.StatusForbidden:
				var got handlers.TokenErrorResponse
				decodeJSON(t, rec, &got)
				if got.Error != tc.wantError {
					t.Errorf("error = %q, want %q", got.Error, tc.wantError)
				}
				challenge := rec.Header().Get("WWW-Authenticate")
				if tc.wantError == "invalid_request" {
					// RFC 6750 section 3.1: no error attributes when the request has no token.
					if want := `Bearer realm="streamonkey"`; challenge != want {
						t.Errorf("WWW-Authenticate = %q, want %q", challenge, want)
					}
					return
				}
				if tc.wantError == "insufficient_scope" {
					if want := `Bearer realm="streamonkey", error="insufficient_scope", error_description="Missing openid scope"`; challenge != want {
						t.Errorf("WWW-Authenticate = %q, want %q", challenge, want)
					}
					return
				}
				// The header's error_description drops '"' and '\'; the JSON body keeps the raw message.
				desc, hasPrefix := strings.CutPrefix(challenge, invalidTokenChallenge)
				desc, hasSuffix := strings.CutSuffix(desc, `"`)
				if !hasPrefix || !hasSuffix || strings.ContainsAny(desc, `"\`) || !strings.Contains(desc, strings.ReplaceAll(tc.wantReason, `"`, "")) {
					t.Errorf("WWW-Authenticate = %q, want prefix %q, a description without '\"' or '\\' containing %q, and a closing '\"'", challenge, invalidTokenChallenge, tc.wantReason)
				}
				if !strings.Contains(got.ErrorDescription, tc.wantReason) {
					t.Errorf("error_description = %q, want it to contain %q", got.ErrorDescription, tc.wantReason)
				}
			}
		})
	}
}
