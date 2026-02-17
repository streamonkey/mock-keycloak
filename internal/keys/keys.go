package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
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

// InitFromFile loads the RSA private key from the given PEM file.
// If the file does not exist, a new key pair is generated and saved to the file.
// Panics on failure.
func InitFromFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Generate new key and save it
			privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic("failed to generate RSA key: " + err.Error())
			}
			if err := savePrivateKey(path, privateKey); err != nil {
				panic("failed to save private key: " + err.Error())
			}
		} else {
			panic("failed to read key file: " + err.Error())
		}
	} else {
		privateKey, err = parsePrivateKey(data)
		if err != nil {
			panic("failed to parse private key: " + err.Error())
		}
	}

	keyID = deriveKeyID(&privateKey.PublicKey)
}

// parsePrivateKey parses a PEM-encoded PKCS#8 or PKCS#1 private key.
func parsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	// Try PKCS#8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS#1
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// savePrivateKey saves the private key to a PEM file in PKCS#8 format.
func savePrivateKey(path string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// deriveKeyID generates a stable key ID from the public key.
// Uses first 16 chars of base64url(SHA-256(DER-encoded public key)).
func deriveKeyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic("failed to marshal public key: " + err.Error())
	}
	hash := sha256.Sum256(der)
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])
	return encoded[:16]
}

// GetPrivateKey returns the generated private key
func GetPrivateKey() *rsa.PrivateKey {
	return privateKey
}

// GetPublicKey returns the public key corresponding to the private key
func GetPublicKey() *rsa.PublicKey {
	return &privateKey.PublicKey
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
