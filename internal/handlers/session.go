package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const sessionCookieName = "MOCK_KEYCLOAK_SESSION"

// setSessionCookie sets the session cookie with the user index and session state.
// Cookie value format: "<userIndex>/<sessionState>"
func setSessionCookie(w http.ResponseWriter, userIndex int, sessionState string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    fmt.Sprintf("%d/%s", userIndex, sessionState),
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	})
}

// getSessionCookie reads and parses the session cookie.
// Returns the user index, session state, and whether a valid cookie was found.
func getSessionCookie(r *http.Request) (userIndex int, sessionState string, ok bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return 0, "", false
	}

	parts := strings.SplitN(cookie.Value, "/", 2)
	if len(parts) != 2 {
		return 0, "", false
	}

	idx, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", false
	}

	return idx, parts[1], true
}

// clearSessionCookie removes the session cookie by setting MaxAge to -1.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	})
}
