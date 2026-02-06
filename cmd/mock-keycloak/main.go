package main

import (
	"log"
	"net/http"
	"os"

	"gitlab.streamonkey.net/testing/mock-keycloak/internal/config"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/handlers"
	"gitlab.streamonkey.net/testing/mock-keycloak/internal/keys"
)

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

	// Initialize RSA keys
	keys.Init()

	// Register routes (with CORS for browser clients)
	http.HandleFunc("/realms/mock/.well-known/openid-configuration", cors(handlers.HandleOpenIDConfig(cfg.BaseURL)))
	http.HandleFunc("/realms/mock/protocol/openid-connect/certs", cors(handlers.HandleJWKS()))
	http.HandleFunc("/realms/mock/protocol/openid-connect/login-status-iframe.html", handlers.HandleLoginStatusIframe())
	http.HandleFunc("/realms/mock/protocol/openid-connect/login-status-iframe.html/init", cors(handlers.HandleIframeInit()))
	http.HandleFunc("/realms/mock/protocol/openid-connect/3p-cookies/step1.html", handlers.Handle3pCookiesStep1())
	http.HandleFunc("/realms/mock/protocol/openid-connect/3p-cookies/step2.html", handlers.Handle3pCookiesStep2())
	http.HandleFunc("/realms/mock/protocol/openid-connect/auth", handlers.HandleAuth())
	http.HandleFunc("/realms/mock/protocol/openid-connect/token", cors(handlers.HandleToken(cfg.BaseURL, cfg.DefaultUser)))
	http.HandleFunc("/realms/mock/protocol/openid-connect/logout", cors(handlers.HandleLogout()))
	http.HandleFunc("/realms/mock/get-signed-mock-token", cors(handlers.HandleGetToken(cfg.BaseURL)))

	log.Printf("Starting mock-keycloak server on %s", cfg.Addr)
	log.Printf("Base URL: %s", cfg.BaseURL)
	log.Printf("Issuer: %s/realms/mock", cfg.BaseURL)

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
