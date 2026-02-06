package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/google/uuid"
)

var (
	privateKey *rsa.PrivateKey
	keyID      string
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Init generates a new RSA key pair. Panics on failure.
func Init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate RSA key: " + err.Error())
	}
	keyID = uuid.New().String()
}

// GetPrivateKey returns the generated private key
func GetPrivateKey() *rsa.PrivateKey {
	return privateKey
}

// GetKeyID returns the key ID
func GetKeyID() string {
	return keyID
}

// GetJWKS returns the public key as a JWKS
func GetJWKS() JWKS {
	pub := &privateKey.PublicKey

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: keyID,
				N:   base64URLEncode(pub.N.Bytes()),
				E:   base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
