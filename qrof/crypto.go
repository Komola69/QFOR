package qrof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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

func DeriveOID(pub ed25519.PublicKey, objectNonce [16]byte) [32]byte {
	buf := make([]byte, len(pub)+16)
	copy(buf, pub)
	copy(buf[len(pub):], objectNonce[:])
	return sha256.Sum256(buf)
}

func BuildDataSigningMessage(version uint8, oid [32]byte, chunkIndex uint16, totalChunks uint16, payload []byte) []byte {
	payloadHash := sha256.Sum256(payload)

	msg := make([]byte, 1+32+2+2+32)
	msg[0] = version
	copy(msg[1:33], oid[:])
	binary.BigEndian.PutUint16(msg[33:35], chunkIndex)
	binary.BigEndian.PutUint16(msg[35:37], totalChunks)
	copy(msg[37:], payloadHash[:])

	return msg
}

func SignData(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

func VerifySignature(pub ed25519.PublicKey, message, sig []byte) bool {
	valid := ed25519.Verify(pub, message, sig)
	if !valid {
		fmt.Println("[DEBUG] Signature verification FAILED")
	}
	return valid
}
