package qrof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
)

func LoadOrGenerateIdentity(filepath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath)
	if err == nil {
		if len(raw) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid private key size in %s: got %d", filepath, len(raw))
		}
		priv := ed25519.PrivateKey(raw)
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return nil, nil, errors.New("failed to derive public key from private key")
		}
		return append(ed25519.PublicKey(nil), pub...), append(ed25519.PrivateKey(nil), priv...), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath, priv, 0o600); err != nil {
		return nil, nil, err
	}

	return append(ed25519.PublicKey(nil), pub...), append(ed25519.PrivateKey(nil), priv...), nil
}

func DeriveOID(pub ed25519.PublicKey) [32]byte {
	return sha256.Sum256(pub)
}

func BuildDataSigningMessage(oid [32]byte, payload []byte) []byte {
	msg := make([]byte, len(oid)+len(payload))
	copy(msg, oid[:])
	copy(msg[len(oid):], payload)
	return msg
}

func SignData(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

func VerifySignature(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}
