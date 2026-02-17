package token

import "github.com/golang-jwt/jwt/v5"

// RoleAccess represents a set of roles for a resource
type RoleAccess struct {
	Roles []string `json:"roles"`
}

// Request represents the input for token generation
type Request struct {
	Sub               string                `json:"sub"`
	Azp               string                `json:"azp"`
	Aud               []string              `json:"aud"`
	Sid               string                `json:"sid,omitempty"` // session ID; if empty, a random one is generated
	AllowedOrigins    []string              `json:"allowed_origins"`
	RealmAccess       RoleAccess            `json:"realm_access"`
	ResourceAccess    map[string]RoleAccess `json:"resource_access"`
	Scope             string                `json:"scope"`
	EmailVerified     bool                  `json:"email_verified"`
	Name              string                `json:"name"`
	Groups            []string              `json:"groups"`
	PreferredUsername string                `json:"preferred_username"`
	GivenName         string                `json:"given_name"`
	FamilyName        string                `json:"family_name"`
	Email             string                `json:"email"`
	ExpSeconds        int64                 `json:"exp_seconds"`
}

// KeycloakClaims represents the full JWT claims for a Keycloak access token
type KeycloakClaims struct {
	jwt.RegisteredClaims

	// Keycloak specific fields
	AuthTime          int64                 `json:"auth_time"`
	Typ               string                `json:"typ"`
	Azp               string                `json:"azp"`
	Sid               string                `json:"sid"`
	Acr               string                `json:"acr"`
	AllowedOrigins    []string              `json:"allowed-origins,omitempty"`
	RealmAccess       RoleAccess            `json:"realm_access,omitempty"`
	ResourceAccess    map[string]RoleAccess `json:"resource_access,omitempty"`
	Scope             string                `json:"scope,omitempty"`
	EmailVerified     bool                  `json:"email_verified,omitempty"`
	Name              string                `json:"name,omitempty"`
	Groups            []string              `json:"groups,omitempty"`
	PreferredUsername string                `json:"preferred_username,omitempty"`
	GivenName         string                `json:"given_name,omitempty"`
	FamilyName        string                `json:"family_name,omitempty"`
	Email             string                `json:"email,omitempty"`
}

// IDTokenClaims represents the JWT claims for an OIDC ID token
type IDTokenClaims struct {
	jwt.RegisteredClaims

	AuthTime          int64  `json:"auth_time"`
	Typ               string `json:"typ"`
	Azp               string `json:"azp"`
	Sid               string `json:"sid"`
	Acr               string `json:"acr"`
	Nonce             string `json:"nonce,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Email             string `json:"email,omitempty"`
}

// RefreshTokenClaims represents the JWT claims for a refresh token
type RefreshTokenClaims struct {
	jwt.RegisteredClaims

	Typ string `json:"typ"`
	Sid string `json:"sid"`
}
