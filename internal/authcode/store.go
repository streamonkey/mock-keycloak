package authcode

import (
	"sync"

	"github.com/google/uuid"
)

// AuthCodeData stores metadata associated with an authorization code
type AuthCodeData struct {
	ClientID     string
	RedirectURI  string
	Nonce        string
	Scope        string
	ResponseMode string
}

var (
	store = make(map[string]AuthCodeData)
	mu    sync.RWMutex
)

// Generate creates a new authorization code and stores its metadata
func Generate(data AuthCodeData) string {
	code := uuid.New().String()

	mu.Lock()
	store[code] = data
	mu.Unlock()

	return code
}

// Consume retrieves and removes an authorization code's metadata
// Returns the data and true if found, or empty data and false if not found
func Consume(code string) (AuthCodeData, bool) {
	mu.Lock()
	defer mu.Unlock()

	data, ok := store[code]
	if ok {
		delete(store, code)
	}
	return data, ok
}
