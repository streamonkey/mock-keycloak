package handlers

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/authcode"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/config"
)

// loginPageData is the template data passed to login.html.
type loginPageData struct {
	Users  []config.User
	Params map[string]string
}

var loginTmpl = template.Must(
	template.New("login.html").
		Funcs(template.FuncMap{
			"initial": func(name string) string {
				if name == "" {
					return "?"
				}
				return strings.ToUpper(name[:1])
			},
		}).
		Parse(loginHTML),
)

// HandleAuth returns a handler for the authorization endpoint.
// When additional users are configured, a GET request renders a user-selection
// page; otherwise it redirects immediately with an authorization code.
// A POST request (from the selection page) completes the flow.
func HandleAuth(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAuthGet(w, r, cfg)
		case http.MethodPost:
			handleAuthPost(w, r, cfg)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleAuthGet validates the authorization request and either shows the
// user-selection page or redirects immediately.
func handleAuthGet(w http.ResponseWriter, r *http.Request, cfg config.Config) {
	query := r.URL.Query()

	responseType := query.Get("response_type")
	redirectURI := query.Get("redirect_uri")
	clientID := query.Get("client_id")
	scope := query.Get("scope")

	log.Printf("  -> auth GET: client_id=%s response_type=%s redirect_uri=%s scope=%s", clientID, responseType, redirectURI, scope)

	if responseType != "code" {
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	prompt := query.Get("prompt")

	// Check for an existing session.
	sessionUserIndex, _, hasSession := getSessionCookie(r)
	if hasSession && sessionUserIndex >= 0 && sessionUserIndex < len(cfg.Users) {
		log.Printf("  -> auth: existing session found for user index=%d (name=%s)",
			sessionUserIndex, cfg.Users[sessionUserIndex].PreferredUsername)
		finishAuth(w, r, sessionUserIndex, true, query)
		return
	}

	// No session — handle prompt=none (silent SSO check).
	if prompt == "none" {
		log.Printf("  -> auth: prompt=none but no session, returning login_required")
		redirectLoginRequired(w, r, query)
		return
	}

	// If more than one user is configured, show the selection page.
	if len(cfg.Users) > 1 {
		log.Printf("  -> auth: showing user selection page (%d users)", len(cfg.Users))
		renderLoginPage(w, r, cfg)
		return
	}

	// Single user — redirect immediately.
	log.Printf("  -> auth: single user configured, redirecting immediately")
	finishAuth(w, r, 0, true, query)
}

// handleAuthPost is called when the user selects an account on the login page.
func handleAuthPost(w http.ResponseWriter, r *http.Request, cfg config.Config) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	selectedIndex, err := strconv.Atoi(r.FormValue("selected_user_index"))
	if err != nil || selectedIndex < 0 || selectedIndex >= len(cfg.Users) {
		log.Printf("  -> auth POST: invalid user selection: %s", r.FormValue("selected_user_index"))
		http.Error(w, "invalid user selection", http.StatusBadRequest)
		return
	}

	log.Printf("  -> auth POST: user selected index=%d (name=%s)", selectedIndex, cfg.Users[selectedIndex].PreferredUsername)
	responseType := r.FormValue("response_type")
	redirectURI := r.FormValue("redirect_uri")

	if responseType != "code" {
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	// Re-pack form values into url.Values so finishAuth can read them.
	params := url.Values{}
	for k, vs := range r.Form {
		for _, v := range vs {
			params.Set(k, v)
		}
	}

	finishAuth(w, r, selectedIndex, true, params)
}

// renderLoginPage renders the user-selection page.
func renderLoginPage(w http.ResponseWriter, r *http.Request, cfg config.Config) {
	// Carry all original query parameters as hidden form fields.
	params := make(map[string]string)
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}

	data := loginPageData{
		Users:  cfg.Users,
		Params: params,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginTmpl.Execute(w, data); err != nil {
		http.Error(w, "failed to render login page", http.StatusInternalServerError)
	}
}

// redirectLoginRequired redirects to the redirect_uri with error=login_required.
// Used when prompt=none is requested but no session exists.
func redirectLoginRequired(w http.ResponseWriter, r *http.Request, params url.Values) {
	redirectURI := params.Get("redirect_uri")
	state := params.Get("state")
	responseMode := params.Get("response_mode")
	if responseMode == "" {
		responseMode = "fragment"
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	rp := url.Values{}
	rp.Set("error", "login_required")
	if state != "" {
		rp.Set("state", state)
	}

	if responseMode == "fragment" {
		redirectURL.Fragment = rp.Encode()
	} else {
		redirectURL.RawQuery = rp.Encode()
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// finishAuth generates an authorization code, stores it, sets the session
// cookie, and redirects the client to the redirect_uri with the code and state.
func finishAuth(w http.ResponseWriter, r *http.Request, userIndex int, userSelected bool, params url.Values) {
	clientID := params.Get("client_id")
	redirectURI := params.Get("redirect_uri")
	state := params.Get("state")
	responseMode := params.Get("response_mode")
	nonce := params.Get("nonce")
	scope := params.Get("scope")

	if responseMode == "" {
		responseMode = "fragment"
	}

	// Generate a session state identifier for this auth session.
	sessionState := uuid.New().String()

	code := authcode.Generate(authcode.AuthCodeData{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Nonce:        nonce,
		Scope:        scope,
		ResponseMode: responseMode,
		UserIndex:    userIndex,
		UserSelected: userSelected,
	})

	log.Printf("  -> auth: generated code=%s for client_id=%s redirect_uri=%s response_mode=%s session_state=%s", code, clientID, redirectURI, responseMode, sessionState)

	// Set session cookie so subsequent requests auto-select this user.
	setSessionCookie(w, userIndex, sessionState)

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	rp := url.Values{}
	rp.Set("code", code)
	if state != "" {
		rp.Set("state", state)
	}
	rp.Set("session_state", sessionState)

	if responseMode == "fragment" {
		redirectURL.Fragment = rp.Encode()
	} else {
		redirectURL.RawQuery = rp.Encode()
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
