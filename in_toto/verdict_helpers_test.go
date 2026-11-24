package in_toto

import (
	"crypto/x509"
	"encoding/pem"
)

// marshalPKCS8 DER-encodes a private key in PKCS#8. It is kept in test-only
// code so the production package gains no new dependencies.
func marshalPKCS8(priv any) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}

// pemEncode returns the PEM encoding of the given DER bytes.
func pemEncode(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}
