package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	// Command line flags
	issuer := flag.String("issuer", "http://localhost:8080/realms/mock", "OAuth2 issuer URL (realm URL)")
	clientID := flag.String("client-id", "test-client", "OAuth2 client ID")
	clientSecret := flag.String("client-secret", "test-secret", "OAuth2 client secret")
	scopes := flag.String("scopes", "openid", "Comma-separated list of scopes")
	flag.Parse()

	// Build token URL from issuer
	tokenURL := *issuer + "/protocol/openid-connect/token"

	// Configure client credentials
	config := &clientcredentials.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		TokenURL:     tokenURL,
		Scopes:       strings.Split(*scopes, ","),
	}

	log.Printf("Requesting token from: %s", tokenURL)
	log.Printf("Client ID: %s", *clientID)
	log.Printf("Scopes: %s", *scopes)
	fmt.Println()

	// Request token
	ctx := context.Background()
	token, err := config.Token(ctx)
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}

	// Print token info
	fmt.Println("=== Token Response ===")
	fmt.Printf("Access Token: %s...\n", truncate(token.AccessToken, 50))
	fmt.Printf("Token Type: %s\n", token.TokenType)
	fmt.Printf("Expiry: %s\n", token.Expiry)
	fmt.Println()

	// Decode and print the token payload
	parts := strings.Split(token.AccessToken, ".")
	if len(parts) == 3 {
		payload, err := decodeJWTPayload(parts[1])
		if err != nil {
			log.Printf("Failed to decode token payload: %v", err)
		} else {
			fmt.Println("=== Token Payload ===")
			prettyJSON, _ := json.MarshalIndent(payload, "", "  ")
			fmt.Println(string(prettyJSON))
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func decodeJWTPayload(payload string) (map[string]interface{}, error) {
	// Base64URL decode
	jsonBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, err
	}

	return result, nil
}
