package qrof

import (
	"crypto/subtle"
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/sha3"
)

type AdmissionGate struct {
	Difficulty uint32
	QueueSize  int
}

var shake256Pool = sync.Pool{
	New: func() any {
		return sha3.NewShake256()
	},
}

func (g AdmissionGate) MicroAdmit(oid [32]byte, nonce uint32) bool {
	h := shake256Pool.Get().(sha3.ShakeHash)
	h.Reset()

	var nonceBuf [4]byte
	binary.BigEndian.PutUint32(nonceBuf[:], nonce)

	_, _ = h.Write(oid[:])
	_, _ = h.Write(nonceBuf[:])

	var out [4]byte
	_, _ = h.Read(out[:])

	shake256Pool.Put(h)
	return binary.BigEndian.Uint32(out[:]) < g.Difficulty
}

func (g AdmissionGate) InclusionVerify(oid [32]byte, payload []byte, foldedPath []byte) bool {
	var accumulator [32]byte

	for i := 0; i < len(payload); i++ {
		accumulator[i%32] ^= payload[i]
	}
	for i := 0; i < len(foldedPath); i++ {
		accumulator[i%32] ^= foldedPath[i]
	}

	h := shake256Pool.Get().(sha3.ShakeHash)
	h.Reset()
	_, _ = h.Write(accumulator[:])

	var digest [32]byte
	_, _ = h.Read(digest[:])
	shake256Pool.Put(h)

	return subtle.ConstantTimeCompare(digest[:], oid[:]) == 1
}
