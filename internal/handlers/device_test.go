package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/config"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/handlers"
)

func TestDeviceGrant(t *testing.T) {
	cfg := config.Config{Users: []config.User{{Sub: "sub-1", Name: "Wilhelm Bartel", PreferredUsername: "wilhelm.bartel"}}}
	tokenHandler := handlers.HandleToken(testBaseURL, testRealm, cfg)
	poll := func(deviceCode string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		tokenHandler(rec, newRequest(http.MethodPost, "/token", url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":   {"xstream-control"},
			"device_code": {deviceCode},
		}))
		return rec
	}

	rec := httptest.NewRecorder()
	handlers.HandleDeviceAuth(testBaseURL, testRealm)(rec, newRequest(http.MethodPost, "/auth/device",
		url.Values{"client_id": {"xstream-control"}, "scope": {"openid offline_access"}}))
	var start struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURIComplete string `json:"verification_uri_complete"`
	}
	decodeJSON(t, rec, &start)
	if want := testIssuer + "/device?user_code=" + start.UserCode; start.VerificationURIComplete != want {
		t.Errorf("verification_uri_complete = %q, want %q", start.VerificationURIComplete, want)
	}

	var pending map[string]any
	decodeJSON(t, poll(start.DeviceCode), &pending)
	if pending["error"] != "authorization_pending" {
		t.Fatalf("before approval: %v, want authorization_pending", pending)
	}

	rec = httptest.NewRecorder()
	handlers.HandleDevicePage(cfg)(rec, newRequest(http.MethodPost, "/device", url.Values{"user_code": {start.UserCode}, "selected_user_index": {"0"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("approval: status %d, body %q", rec.Code, rec.Body.String())
	}

	var tokens map[string]any
	decodeJSON(t, poll(start.DeviceCode), &tokens)
	if tokens["access_token"] == nil || tokens["refresh_token"] == nil {
		t.Fatalf("after approval: %v, want tokens", tokens)
	}

	var again map[string]any
	decodeJSON(t, poll(start.DeviceCode), &again)
	if again["error"] != "invalid_grant" {
		t.Errorf("second poll: %v, want invalid_grant (codes are single-use)", again)
	}
}
