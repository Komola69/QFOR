package qrof

import "encoding/binary"

const (
	MTU        = 1500
	HeaderSize = 64
)

type QROFPacket struct {
	Preamble    [2]byte
	OID         [32]byte
	FragmentIdx uint16
	PoWNonce    uint32
	MerkleProof []byte
	Payload     []byte
}

func (p QROFPacket) Serialize() []byte {
	frame := make([]byte, MTU)

	preamble := p.Preamble
	if preamble == ([2]byte{}) {
		preamble = [2]byte{0x51, 0x52}
	}
	copy(frame[0:2], preamble[:])
	copy(frame[2:34], p.OID[:])
	binary.BigEndian.PutUint16(frame[34:36], p.FragmentIdx)
	binary.BigEndian.PutUint32(frame[36:40], p.PoWNonce)

	merkleRoom := HeaderSize - 40
	if merkleRoom > 0 && len(p.MerkleProof) > 0 {
		if len(p.MerkleProof) < merkleRoom {
			merkleRoom = len(p.MerkleProof)
		}
		copy(frame[40:40+merkleRoom], p.MerkleProof[:merkleRoom])
	}

	payloadRoom := MTU - HeaderSize
	if len(p.Payload) < payloadRoom {
		payloadRoom = len(p.Payload)
	}
	copy(frame[HeaderSize:HeaderSize+payloadRoom], p.Payload[:payloadRoom])

	return frame
}
