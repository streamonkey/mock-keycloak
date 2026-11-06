package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/config"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/keys"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/token"
)

// Device authorization grant (RFC 8628): a client without a browser asks for a code, the user
// approves it on the /device page by picking a mock user, the client polls the token endpoint.

const deviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code"

type deviceAuth struct {
	clientID  string
	scope     string
	userCode  string
	userIndex int // -1 until approved
	expires   time.Time
}

var (
	devices   = map[string]*deviceAuth{} // by device code
	devicesMu sync.Mutex
)

// HandleDeviceAuth starts a device authorization: POST client_id, scope.
func HandleDeviceAuth(baseURL, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			writeTokenError(w, "invalid_request", "failed to parse form data")
			return
		}
		deviceCode := uuid.New().String()
		userCode := fmt.Sprintf("%04d-%04d", rand.IntN(10000), rand.IntN(10000))
		devicesMu.Lock()
		devices[deviceCode] = &deviceAuth{
			clientID:  r.FormValue("client_id"),
			scope:     r.FormValue("scope"),
			userCode:  userCode,
			userIndex: -1,
			expires:   time.Now().Add(10 * time.Minute),
		}
		devicesMu.Unlock()

		verify := baseURL + "/realms/" + realm + "/device"
		log.Printf("  -> device auth: client_id=%s user_code=%s", r.FormValue("client_id"), userCode)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":               deviceCode,
			"user_code":                 userCode,
			"verification_uri":          verify,
			"verification_uri_complete": verify + "?user_code=" + userCode,
			"expires_in":                600,
			"interval":                  2,
		})
	}
}

// HandleDevicePage approves a user code: it asks for the code unless the link carried it,
// lists the accounts (GET), and approves the code for the chosen one (POST). It looks like the
// sign-in page because it is the same template.
func HandleDevicePage(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCode := strings.TrimSpace(r.FormValue("user_code"))
		data := loginPageData{Title: "Sign in a device"}

		switch {
		case r.Method == http.MethodPost:
			index, err := strconv.Atoi(r.FormValue("selected_user_index"))
			if err != nil || index < 0 || index >= len(cfg.Users) || !approveDevice(userCode, index) {
				data.Subtitle, data.AskCode, data.Error = "Enter the code shown on the device.", true, "This code is unknown or expired."
				break
			}
			log.Printf("  -> device auth: user_code=%s approved as %s", userCode, cfg.Users[index].PreferredUsername)
			data.Subtitle = "Signed in as " + cfg.Users[index].Name + ". The device continues by itself; you can close this page."
		case userCode == "":
			data.Subtitle, data.AskCode = "Enter the code shown on the device.", true
		case !pendingDevice(userCode):
			data.Subtitle, data.AskCode, data.Error = "Enter the code shown on the device.", true, "This code is unknown or expired."
		default:
			data.Subtitle, data.Code = "Select an account to approve", userCode
			data.Users, data.Params = cfg.Users, map[string]string{"user_code": userCode}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := loginTmpl.Execute(w, data); err != nil {
			http.Error(w, "failed to render device page", http.StatusInternalServerError)
		}
	}
}

// pendingDevice reports whether userCode belongs to an unexpired, unapproved authorization.
func pendingDevice(userCode string) bool {
	devicesMu.Lock()
	defer devicesMu.Unlock()
	for _, d := range devices {
		if d.userCode == userCode && d.userIndex < 0 && time.Now().Before(d.expires) {
			return true
		}
	}
	return false
}

func approveDevice(userCode string, index int) bool {
	devicesMu.Lock()
	defer devicesMu.Unlock()
	for _, d := range devices {
		if d.userCode == userCode && time.Now().Before(d.expires) {
			d.userIndex = index
			return true
		}
	}
	return false
}

func handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request, issuer string, cfg config.Config) {
	deviceCode := r.FormValue("device_code")
	devicesMu.Lock()
	d, ok := devices[deviceCode]
	if ok && (d.userIndex >= 0 || time.Now().After(d.expires)) {
		delete(devices, deviceCode)
	}
	devicesMu.Unlock()

	switch {
	case !ok:
		writeTokenError(w, "invalid_grant", "unknown device code")
		return
	case time.Now().After(d.expires):
		writeTokenError(w, "expired_token", "the device code expired")
		return
	case d.userIndex < 0:
		writeTokenError(w, "authorization_pending", "the user has not approved yet")
		return
	}

	user := cfg.Users[d.userIndex]
	sessionState := token.GenerateSessionID()
	req := buildTokenRequest(user, d.clientID, d.scope, sessionState)
	accessToken, err := token.Generate(req, issuer, keys.GetPrivateKey(), keys.GetKeyID())
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate access token")
		return
	}
	idToken, err := token.GenerateIDToken(req, issuer, keys.GetPrivateKey(), keys.GetKeyID(), d.clientID, "")
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate id token")
		return
	}
	refreshToken, err := token.GenerateRefreshToken(req.Sub, issuer, keys.GetPrivateKey(), keys.GetKeyID(), sessionState, req.RefreshExp())
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate refresh token")
		return
	}
	writeTokenResponse(w, TokenResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        req.AccessExp(),
		RefreshToken:     refreshToken,
		RefreshExpiresIn: req.RefreshExp(),
		IDToken:          idToken,
		SessionState:     sessionState,
		Scope:            d.scope,
	})
	log.Printf("  -> device code grant: issued tokens for sub=%s", req.Sub)
}
