package qrof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"math"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

const (
	DifficultyInterest  uint32 = 0x0FFFFFFF
	DifficultyDiscovery uint32 = 0x00FFFFFF

	podScratchSize = 4 * 1024
)

func DeriveNamespace(ns string) [32]byte {
	return sha256.Sum256([]byte(ns))
}

func VerifyA_PoD(interest DemandCapsule, salt [32]byte) bool {
	return VerifyA_PoDWithDifficulty(interest, salt, DifficultyInterest)
}

func VerifyA_PoDWithDifficulty(interest DemandCapsule, salt [32]byte, difficulty uint32) bool {
	digest := computePoDDigest(interest.OID, interest.Nonce, salt)
	if subtle.ConstantTimeCompare(digest[:], interest.SaltedPoD[:]) != 1 {
		return false
	}
	return binary.BigEndian.Uint32(digest[:4]) < difficulty
}

func SolveA_PoD(oid [32]byte, salt [32]byte, difficulty uint32) DemandCapsule {
	var nonce uint32
	for {
		digest := computePoDDigest(oid, nonce, salt)
		if binary.BigEndian.Uint32(digest[:4]) < difficulty {
			return DemandCapsule{
				OID:       oid,
				Nonce:     nonce,
				SaltedPoD: digest,
			}
		}
		nonce++
	}
}

func DeriveSalt(leafHash [32]byte, oid [32]byte) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write(leafHash[:])
	_, _ = h.Write(oid[:])

	var salt [32]byte
	_, _ = h.Read(salt[:])
	return salt
}

func VerifyBeaconPoW(beacon Beacon, difficulty uint32) bool {
	return beaconWorkValue(beacon, beacon.PoW) < difficulty
}

func VerifyDiscoveryPoW(beacon Beacon) bool {
	return VerifyBeaconPoW(beacon, DifficultyDiscovery)
}

func CraftDataPacket(oid [32]byte, pub ed25519.PublicKey, sig, payload []byte) []byte {
	packet := DataPacket{
		OID:       oid,
		PubKey:    append(ed25519.PublicKey(nil), pub...),
		Signature: append([]byte(nil), sig...),
		Payload:   append([]byte(nil), payload...),
	}
	return packet.Serialize()
}

func SolveBeaconPoW(beacon Beacon, difficulty uint32) uint32 {
	var nonce uint32
	for {
		if beaconWorkValue(beacon, nonce) < difficulty {
			return nonce
		}
		nonce++
	}
}

func computePoDDigest(oid [32]byte, nonce uint32, salt [32]byte) [32]byte {
	var interestSeed [36]byte
	copy(interestSeed[:32], oid[:])
	binary.BigEndian.PutUint32(interestSeed[32:], nonce)

	// 4KB memory friction using Argon2id output expanded into a scratch arena.
	base := argon2.IDKey(interestSeed[:], salt[:], 1, 4, 1, 32)
	var scratch [podScratchSize]byte
	for i := 0; i < len(scratch); i++ {
		scratch[i] = base[i%len(base)] ^ byte(i)
	}

	h := sha3.NewShake256()
	_, _ = h.Write(scratch[:])
	_, _ = h.Write(salt[:])
	_, _ = h.Write(oid[:])

	var digest [32]byte
	_, _ = h.Read(digest[:])
	return digest
}

func beaconWorkValue(beacon Beacon, nonce uint32) uint32 {
	h := sha3.NewShake256()
	_, _ = h.Write(beacon.OID[:])
	_, _ = h.Write(beacon.LeafHash[:])

	var potentialBuf [8]byte
	binary.BigEndian.PutUint64(potentialBuf[:], math.Float64bits(beacon.Potential))
	_, _ = h.Write(potentialBuf[:])

	var epochBuf [4]byte
	binary.BigEndian.PutUint32(epochBuf[:], beacon.Epoch)
	_, _ = h.Write(epochBuf[:])

	var nonceBuf [4]byte
	binary.BigEndian.PutUint32(nonceBuf[:], nonce)
	_, _ = h.Write(nonceBuf[:])

	var out [4]byte
	_, _ = h.Read(out[:])
	return binary.BigEndian.Uint32(out[:])
}
