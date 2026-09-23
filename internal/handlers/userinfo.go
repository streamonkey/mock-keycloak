package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/keys"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/token"
)

// userInfoResponse holds the OIDC standard profile claims served by the
// userinfo endpoint. Roles and groups are left out on purpose: Keycloak's
// default mappers do not put them into userinfo either.
type userInfoResponse struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified"`
}

// HandleUserInfo returns a handler for the OIDC userinfo endpoint.
// The claims are taken from the validated access token itself, not from the
// config, so tokens minted via get-signed-mock-token work as well.
func HandleUserInfo(baseURL, realm string) http.HandlerFunc {
	issuer := baseURL + "/realms/" + realm

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tokenString := bearerToken(r)
		if tokenString == "" {
			// RFC 6750 section 3.1: a request without any token gets a
			// challenge without error attributes.
			log.Printf("  -> userinfo: 401 (no access token)")
			writeUserInfoError(w, http.StatusUnauthorized, fmt.Sprintf(`Bearer realm="%s"`, realm), "invalid_request", "access token not provided")
			return
		}

		claims := &token.KeycloakClaims{}
		if err := verifyToken(tokenString, issuer, claims); err != nil {
			log.Printf("  -> userinfo: 401 (invalid token: %v)", err)
			writeInvalidToken(w, realm, err.Error())
			return
		}
		if claims.Typ != "Bearer" {
			log.Printf("  -> userinfo: 401 (not an access token, typ=%s)", claims.Typ)
			writeInvalidToken(w, realm, "not an access token (typ="+claims.Typ+")")
			return
		}
		if claims.Subject == "" {
			log.Printf("  -> userinfo: 401 (token has no sub)")
			writeInvalidToken(w, realm, "token has no sub")
			return
		}
		// Keycloak (20.0.0 and later) refuses an access token whose scope
		// lacks openid, e.g. a client_credentials token requested without it.
		if !slices.Contains(strings.Fields(claims.Scope), "openid") {
			log.Printf("  -> userinfo: 403 (missing openid scope, scope=%q)", claims.Scope)
			writeUserInfoError(w, http.StatusForbidden, fmt.Sprintf(`Bearer realm="%s", error="insufficient_scope", error_description="Missing openid scope"`, realm), "insufficient_scope", "Missing openid scope")
			return
		}

		log.Printf("  -> userinfo: 200 (sub=%s preferred_username=%s)", claims.Subject, claims.PreferredUsername)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfoResponse{
			Sub:               claims.Subject,
			Name:              claims.Name,
			PreferredUsername: claims.PreferredUsername,
			GivenName:         claims.GivenName,
			FamilyName:        claims.FamilyName,
			Email:             claims.Email,
			EmailVerified:     claims.EmailVerified,
		})
	}
}

// verifyToken parses tokenString into claims the way userinfo and
// introspection both need it: RS256 only, signed by the mock key, not
// expired, and issued by issuer.
func verifyToken(tokenString, issuer string, claims jwt.Claims) error {
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return keys.GetPublicKey(), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(issuer))
	return err
}

// bearerToken returns the access token from the Authorization header (scheme
// matched case-insensitively) or, on POST, from the access_token form
// parameter (RFC 6750 section 2.2). It returns "" when there is none.
func bearerToken(r *http.Request) string {
	if scheme, t, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return strings.TrimSpace(t)
	}
	if r.Method == http.MethodPost {
		return r.PostFormValue("access_token")
	}
	return ""
}

// writeInvalidToken answers 401 with an RFC 6750 section 3 invalid_token
// challenge.
func writeInvalidToken(w http.ResponseWriter, realm, description string) {
	challenge := fmt.Sprintf(`Bearer realm="%s", error="invalid_token", error_description="%s"`, realm, quotedStringSafe(description))
	writeUserInfoError(w, http.StatusUnauthorized, challenge, "invalid_token", description)
}

func writeUserInfoError(w http.ResponseWriter, status int, challenge, errorCode, description string) {
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(TokenErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// quotedStringSafe drops the characters RFC 6750 section 3 does not allow in
// error_description, so a jwt error message (which can quote the offending
// JSON character) cannot break the challenge's quoting.
func quotedStringSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, s)
}
