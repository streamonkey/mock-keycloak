package main

import (
	"log"
	"net/http"
	"os"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/config"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/handlers"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/keys"
)

// logRequest wraps a handler to log every incoming request with method, path, and query
func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			log.Printf("%s %s?%s (from %s)", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
		} else {
			log.Printf("%s %s (from %s)", r.Method, r.URL.Path, r.RemoteAddr)
		}
		next(w, r)
	}
}

// cors wraps a handler to add CORS headers for browser clients
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			log.Printf("  -> CORS preflight response (204)")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

func main() {
	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.json"
	}

	cfg := config.Load(configPath)

	// Initialize RSA keys from file (generates and saves if not exists)
	keys.InitFromFile(cfg.SigningKeyFile)

	// Register routes (with CORS for browser clients, all wrapped in request logging)
	realm := "/realms/" + cfg.Realm
	http.HandleFunc(realm+"/.well-known/openid-configuration", logRequest(cors(handlers.HandleOpenIDConfig(cfg.BaseURL, cfg.Realm))))
	http.HandleFunc(realm+"/protocol/openid-connect/certs", logRequest(cors(handlers.HandleJWKS())))
	http.HandleFunc(realm+"/protocol/openid-connect/login-status-iframe.html", logRequest(handlers.HandleLoginStatusIframe()))
	http.HandleFunc(realm+"/protocol/openid-connect/login-status-iframe.html/init", logRequest(cors(handlers.HandleIframeInit())))
	http.HandleFunc(realm+"/protocol/openid-connect/3p-cookies/step1.html", logRequest(handlers.Handle3pCookiesStep1()))
	http.HandleFunc(realm+"/protocol/openid-connect/3p-cookies/step2.html", logRequest(handlers.Handle3pCookiesStep2()))
	http.HandleFunc(realm+"/protocol/openid-connect/auth", logRequest(handlers.HandleAuth(cfg)))
	http.HandleFunc(realm+"/protocol/openid-connect/token", logRequest(cors(handlers.HandleToken(cfg.BaseURL, cfg.Realm, cfg))))
	http.HandleFunc(realm+"/protocol/openid-connect/logout", logRequest(cors(handlers.HandleLogout())))
	http.HandleFunc(realm+"/account", logRequest(cors(handlers.HandleAccount(cfg.BaseURL, cfg))))
	http.HandleFunc(realm+"/get-signed-mock-token", logRequest(cors(handlers.HandleGetToken(cfg.BaseURL, cfg.Realm))))

	// health check endpoint
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("Starting mock-keycloak server on %s", cfg.Addr)
	log.Printf("Base URL: %s", cfg.BaseURL)
	log.Printf("Realm: %s", cfg.Realm)
	log.Printf("Issuer: %s/realms/%s", cfg.BaseURL, cfg.Realm)

	var err error
	if cfg.TLS.Enabled() {
		log.Printf("TLS enabled (cert: %s, key: %s)", cfg.TLS.CertFile, cfg.TLS.KeyFile)
		err = http.ListenAndServeTLS(cfg.Addr, cfg.TLS.CertFile, cfg.TLS.KeyFile, nil)
	} else {
		err = http.ListenAndServe(cfg.Addr, nil)
	}
	if err != nil {
		panic("failed to start server: " + err.Error())
	}
}
