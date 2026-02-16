package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
)

//go:embed index.html
var content embed.FS

type PageData struct {
	KeycloakURL string
	ClientID    string
	RedirectURI string
}

const addr = ":3000"
const keycloakURL = "https://local.streamonkey.net:10101"
const clientID = "test-client"

func main() {
	// Parse template
	tmpl, err := template.ParseFS(content, "index.html")
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	// Handler for the main page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Build redirect URI from request
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
			scheme = fwdProto
		}
		redirectURI := fmt.Sprintf("%s://%s/", scheme, r.Host)

		data := PageData{
			KeycloakURL: keycloakURL,
			ClientID:    clientID,
			RedirectURI: redirectURI,
		}

		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Printf("Starting test PKCE client on %s", addr)
	log.Printf("Keycloak URL: %s", keycloakURL)
	log.Printf("Client ID: %s", clientID)
	log.Printf("Open https://local.streamonkey.net%s in your browser", addr)

	if err := http.ListenAndServeTLS(addr, "certs/local.streamonkey.net.crt", "certs/local.streamonkey.net.key", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
