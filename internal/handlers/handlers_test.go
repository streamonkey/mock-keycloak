package handlers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/handlers"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/keys"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/token"
)

const (
	testBaseURL = "http://mock-keycloak.test"
	testRealm   = "streamonkey"
	testIssuer  = testBaseURL + "/realms/" + testRealm
)

// foreignKey signs tokens the mock must not accept.
var foreignKey *rsa.PrivateKey

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mock-keycloak-handlers-")
	if err != nil {
		panic(err)
	}
	keys.InitFromFile(filepath.Join(dir, "jwt-signing.key"))
	foreignKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// testUser is the profile the valid test tokens carry.
var testUser = token.Request{
	Sub:               "00000000-0000-0000-0000-000000000001",
	Azp:               "test-client",
	Aud:               []string{"test-client", "account"},
	Scope:             "openid",
	EmailVerified:     true,
	Name:              "Alice Admin",
	Groups:            []string{"admins"},
	PreferredUsername: "alice",
	GivenName:         "Alice",
	FamilyName:        "Admin",
	Email:             "alice@example.com",
	RealmAccess:       token.RoleAccess{Roles: []string{"admin"}},
	ResourceAccess:    map[string]token.RoleAccess{"dashboard": {Roles: []string{"pro"}}},
}

// testTokens are the tokens the table tests run against.
type testTokens struct {
	access      string // access token for testUser
	minimal     string // access token carrying only a sub and the openid scope
	noOpenID    string // access token for testUser whose scope lacks openid
	noSub       string // access token with the openid scope but no sub
	id          string
	refresh     string
	expired     string // access token, expired a minute ago
	foreign     string // access token signed by foreignKey
	rs512       string // access token signed with the mock key, but RS512
	wrongIssuer string
}

func mintTestTokens(t *testing.T) testTokens {
	t.Helper()
	key, kid := keys.GetPrivateKey(), keys.GetKeyID()
	must := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("minting test token: %v", err)
		}
		return s
	}

	noOpenID := testUser
	noOpenID.Scope = "profile email"

	return testTokens{
		access:      must(token.Generate(testUser, testIssuer, key, kid)),
		minimal:     must(token.Generate(token.Request{Sub: "minted-only", Scope: "openid"}, testIssuer, key, kid)),
		noOpenID:    must(token.Generate(noOpenID, testIssuer, key, kid)),
		noSub:       must(token.Generate(token.Request{Scope: "openid"}, testIssuer, key, kid)),
		id:          must(token.GenerateIDToken(testUser, testIssuer, key, kid, testUser.Azp, "nonce")),
		refresh:     must(token.GenerateRefreshToken(testUser.Sub, testIssuer, key, kid, "session", 1800)),
		expired:     must(signed(jwt.SigningMethodRS256, accessClaims(time.Now().Add(-time.Minute)))),
		foreign:     must(token.Generate(testUser, testIssuer, foreignKey, kid)),
		rs512:       must(signed(jwt.SigningMethodRS512, accessClaims(time.Now().Add(5*time.Minute)))),
		wrongIssuer: must(token.Generate(testUser, "http://elsewhere.test/realms/"+testRealm, key, kid)),
	}
}

// accessClaims builds access token claims with the given expiry, for the
// tokens token.Generate cannot produce: it always expires in five minutes
// and always signs RS256.
func accessClaims(exp time.Time) token.KeycloakClaims {
	return token.KeycloakClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Subject:   testUser.Sub,
			IssuedAt:  jwt.NewNumericDate(exp.Add(-5 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Typ:               "Bearer",
		Azp:               testUser.Azp,
		PreferredUsername: testUser.PreferredUsername,
	}
}

// signed signs claims with the mock key using method.
func signed(method jwt.SigningMethod, claims jwt.Claims) (string, error) {
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = keys.GetKeyID()
	return tok.SignedString(keys.GetPrivateKey())
}

// newRequest builds a request; a non-nil form becomes an
// application/x-www-form-urlencoded body.
func newRequest(method, target string, form url.Values) *http.Request {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return req
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decoding body %q: %v", rec.Body.String(), err)
	}
}

func TestOpenIDConfig_AdvertisesUserinfoAndIntrospection(t *testing.T) {
	rec := httptest.NewRecorder()
	handlers.HandleOpenIDConfig(testBaseURL, testRealm)(rec, httptest.NewRequest(http.MethodGet, "/realms/"+testRealm+"/.well-known/openid-configuration", nil))

	var doc map[string]any
	decodeJSON(t, rec, &doc)

	tests := []struct {
		field string
		want  string
	}{
		{"userinfo_endpoint", testIssuer + "/protocol/openid-connect/userinfo"},
		{"introspection_endpoint", testIssuer + "/protocol/openid-connect/token/introspect"},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			if got := doc[tc.field]; got != tc.want {
				t.Errorf("%s = %v, want %s", tc.field, got, tc.want)
			}
		})
	}
}
