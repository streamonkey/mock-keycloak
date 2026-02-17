package config

import (
	"encoding/json"
	"os"
)

// RoleAccess represents a set of roles for a resource
type RoleAccess struct {
	Roles []string `json:"roles"`
}

// User represents user claims for generated tokens
type User struct {
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
	BaseURL        string          `json:"baseURL"`
	Addr           string          `json:"addr"`
	Realm          string          `json:"realm"`
	SigningKeyFile string          `json:"signingKeyFile"`
	TLS            TLSConfig       `json:"tls"`
	Users          []User          `json:"users"`
	Clients        map[string]User `json:"clients"`
}

// GetUserForClient returns the user configuration for the given client ID.
// Falls back to the first user if the client is not explicitly configured.
func (c Config) GetUserForClient(clientID string) User {
	if user, ok := c.Clients[clientID]; ok {
		return user
	}
	return c.Users[0]
}

// GetUserBySub returns the user with the given subject ID and true if found,
// or a zero User and false if no user matches.
func (c Config) GetUserBySub(sub string) (User, bool) {
	for _, u := range c.Users {
		if u.Sub == sub {
			return u, true
		}
	}
	return User{}, false
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

	if cfg.Realm == "" {
		cfg.Realm = "mock"
	}

	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}

	if cfg.SigningKeyFile == "" {
		cfg.SigningKeyFile = "jwt-signing.key"
	}

	if len(cfg.Users) == 0 {
		panic("at least one user must be configured in the users array")
	}

	// Normalize nil slices to empty slices so they marshal as [] instead of null.
	for i := range cfg.Users {
		normalizeUser(&cfg.Users[i])
	}
	for k, v := range cfg.Clients {
		normalizeUser(&v)
		cfg.Clients[k] = v
	}

	return cfg
}

// normalizeUser ensures all slice fields are non-nil so they marshal as []
// instead of null in JSON.
func normalizeUser(u *User) {
	if u.Groups == nil {
		u.Groups = []string{}
	}
	if u.RealmAccess.Roles == nil {
		u.RealmAccess.Roles = []string{}
	}
	if u.ResourceAccess == nil {
		u.ResourceAccess = map[string]RoleAccess{}
	}
	for k, ra := range u.ResourceAccess {
		if ra.Roles == nil {
			ra.Roles = []string{}
			u.ResourceAccess[k] = ra
		}
	}
}
