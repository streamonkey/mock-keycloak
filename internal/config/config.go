package config

import (
	"encoding/json"
	"os"
)

// RoleAccess represents a set of roles for a resource
type RoleAccess struct {
	Roles []string `json:"roles"`
}

// DefaultUser represents the default user claims for generated tokens
type DefaultUser struct {
	Sub               string                `json:"sub"`
	Name              string                `json:"name"`
	Email             string                `json:"email"`
	EmailVerified     bool                  `json:"email_verified"`
	PreferredUsername string                `json:"preferred_username"`
	GivenName         string                `json:"given_name"`
	FamilyName        string                `json:"family_name"`
	Groups            []string              `json:"groups"`
	RealmAccess       RoleAccess            `json:"realm_access"`
	ResourceAccess    map[string]RoleAccess `json:"resource_access"`
}

// TLSConfig holds TLS certificate configuration
type TLSConfig struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Enabled returns true if TLS is configured
func (t TLSConfig) Enabled() bool {
	return t.CertFile != "" && t.KeyFile != ""
}

type Config struct {
	BaseURL        string                 `json:"baseURL"`
	Addr           string                 `json:"addr"`
	SigningKeyFile string                 `json:"signingKeyFile"`
	TLS            TLSConfig              `json:"tls"`
	DefaultUser    DefaultUser            `json:"defaultUser"`
	Clients        map[string]DefaultUser `json:"clients"`
}

// GetUserForClient returns the user configuration for the given client ID.
// Falls back to DefaultUser if the client is not explicitly configured.
func (c Config) GetUserForClient(clientID string) DefaultUser {
	if user, ok := c.Clients[clientID]; ok {
		return user
	}
	return c.DefaultUser
}

// Load reads the configuration from the given JSON file path.
// Panics if the file cannot be read or parsed.
func Load(path string) Config {
	data, err := os.ReadFile(path)
	if err != nil {
		panic("failed to read config file: " + err.Error())
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		panic("failed to parse config file: " + err.Error())
	}

	if cfg.BaseURL == "" {
		panic("baseURL is required in config")
	}

	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}

	if cfg.SigningKeyFile == "" {
		cfg.SigningKeyFile = "jwt-signing.key"
	}

	return cfg
}
