package token

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Generate creates a signed JWT access token from the request
func Generate(req Request, issuer string, privateKey *rsa.PrivateKey, kid string) (string, error) {
	now := time.Now()

	// Default expiration to 5 minutes if not specified
	expSeconds := req.ExpSeconds
	if expSeconds == 0 {
		expSeconds = 300
	}

	sid := req.Sid
	if sid == "" {
		sid = GenerateSessionID()
	}

	claims := KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   req.Sub,
			Audience:  req.Aud,
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expSeconds) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "onrtac:" + uuid.New().String(),
		},
		AuthTime:          now.Unix(),
		Typ:               "Bearer",
		Azp:               req.Azp,
		Sid:               sid,
		Acr:               "0",
		AllowedOrigins:    req.AllowedOrigins,
		RealmAccess:       req.RealmAccess,
		ResourceAccess:    req.ResourceAccess,
		Scope:             req.Scope,
		EmailVerified:     req.EmailVerified,
		Name:              req.Name,
		Groups:            req.Groups,
		PreferredUsername: req.PreferredUsername,
		GivenName:         req.GivenName,
		FamilyName:        req.FamilyName,
		Email:             req.Email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	return token.SignedString(privateKey)
}

// GenerateIDToken creates a signed JWT ID token (includes nonce for OIDC)
func GenerateIDToken(req Request, issuer string, privateKey *rsa.PrivateKey, kid string, clientID string, nonce string) (string, error) {
	now := time.Now()

	expSeconds := req.ExpSeconds
	if expSeconds == 0 {
		expSeconds = 300
	}

	idSid := req.Sid
	if idSid == "" {
		idSid = GenerateSessionID()
	}

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   req.Sub,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expSeconds) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "onrtac:" + uuid.New().String(),
		},
		AuthTime:          now.Unix(),
		Typ:               "ID",
		Azp:               clientID,
		Sid:               idSid,
		Acr:               "0",
		Nonce:             nonce,
		EmailVerified:     req.EmailVerified,
		Name:              req.Name,
		PreferredUsername: req.PreferredUsername,
		GivenName:         req.GivenName,
		FamilyName:        req.FamilyName,
		Email:             req.Email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	return token.SignedString(privateKey)
}

// GenerateRefreshToken creates a signed JWT refresh token
func GenerateRefreshToken(sub string, issuer string, privateKey *rsa.PrivateKey, kid string, sessionState string) (string, error) {
	now := time.Now()

	claims := RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "onrtac:" + uuid.New().String(),
		},
		Typ: "Refresh",
		Sid: sessionState,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	return token.SignedString(privateKey)
}

// GenerateSessionID generates a random session ID similar to Keycloak's format
func GenerateSessionID() string {
	id := uuid.New().String()
	// Take first 24 chars without dashes for a shorter ID
	clean := ""
	for _, c := range id {
		if c != '-' {
			clean += string(c)
		}
	}
	if len(clean) > 24 {
		clean = clean[:24]
	}
	return clean
}
