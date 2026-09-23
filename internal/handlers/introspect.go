package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// HandleIntrospect returns a handler for the RFC 7662 token introspection
// endpoint. Client authentication (HTTP Basic or client_id/client_secret) is
// accepted without validation, like everywhere else in the mock. Access, ID
// and refresh tokens are all introspected; a token that fails verification
// is reported as {"active":false} and nothing else (RFC 7662 section 2.2).
func HandleIntrospect(baseURL, realm string) http.HandlerFunc {
	issuer := baseURL + "/realms/" + realm

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			writeTokenError(w, "invalid_request", "failed to parse form data")
			return
		}

		clientID := r.PostFormValue("client_id")
		if clientID == "" {
			if basicID, _, ok := r.BasicAuth(); ok {
				clientID = basicID
			}
		}
		// token_type_hint is accepted and ignored: every token type is tried the same way.
		log.Printf("  -> introspect: client_id=%s token_type_hint=%s", clientID, r.PostFormValue("token_type_hint"))

		tokenString := r.PostFormValue("token")
		if tokenString == "" {
			log.Printf("  -> introspect: missing token parameter")
			writeTokenError(w, "invalid_request", "missing token parameter")
			return
		}

		w.Header().Set("Content-Type", "application/json")

		claims := jwt.MapClaims{}
		if err := verifyToken(tokenString, issuer, claims); err != nil {
			log.Printf("  -> introspect: inactive (%v)", err)
			json.NewEncoder(w).Encode(map[string]bool{"active": false})
			return
		}

		claims["active"] = true
		if azp, ok := claims["azp"].(string); ok && azp != "" {
			claims["client_id"] = azp
		}
		if username, ok := claims["preferred_username"].(string); ok && username != "" {
			claims["username"] = username
		}
		if typ, ok := claims["typ"].(string); ok && typ != "" {
			claims["token_type"] = typ
		}

		log.Printf("  -> introspect: active (sub=%v token_type=%v)", claims["sub"], claims["token_type"])
		json.NewEncoder(w).Encode(claims)
	}
}
