package qrof

import (
	"encoding/binary"
	"math"
)

const (
	MTU        = 800
	HeaderSize = 64

	qrofPreamble0 = 0x51
	qrofPreamble1 = 0x52

	FrameTypeBeacon   = 0xB1
	FrameTypeInterest = 0xA1
)

const (
	beaconFrameLen   = 2 + 1 + 32 + 32 + 8 + 4 + 4
	interestFrameLen = 2 + 1 + 32 + 4 + 32
)

var defaultPreamble = [2]byte{qrofPreamble0, qrofPreamble1}

type QROFPacket struct {
	Preamble    [2]byte
	OID         [32]byte
	FragmentIdx uint16
	PoWNonce    uint32
	MerkleProof []byte
	Payload     []byte
}

type Beacon struct {
	OID       [32]byte
	LeafHash  [32]byte
	Potential float64
	Epoch     uint32
	PoW       uint32
}

type DemandCapsule struct {
	OID       [32]byte
	Nonce     uint32
	SaltedPoD [32]byte
}

type InterestPacket struct {
	Preamble      [2]byte
	DemandCapsule DemandCapsule
}

func (p QROFPacket) Serialize() []byte {
	frame := make([]byte, MTU)

	preamble := p.Preamble
	if preamble == ([2]byte{}) {
		preamble = defaultPreamble
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

func (b Beacon) Serialize() []byte {
	frame := make([]byte, beaconFrameLen)
	copy(frame[0:2], defaultPreamble[:])
	frame[2] = FrameTypeBeacon
	copy(frame[3:35], b.OID[:])
	copy(frame[35:67], b.LeafHash[:])
	binary.BigEndian.PutUint64(frame[67:75], math.Float64bits(b.Potential))
	binary.BigEndian.PutUint32(frame[75:79], b.Epoch)
	binary.BigEndian.PutUint32(frame[79:83], b.PoW)
	return frame
}

func ParseBeacon(frame []byte) (Beacon, bool) {
	var b Beacon
	if len(frame) < beaconFrameLen {
		return b, false
	}
	if frame[0] != qrofPreamble0 || frame[1] != qrofPreamble1 || frame[2] != FrameTypeBeacon {
		return b, false
	}

	copy(b.OID[:], frame[3:35])
	copy(b.LeafHash[:], frame[35:67])
	b.Potential = math.Float64frombits(binary.BigEndian.Uint64(frame[67:75]))
	b.Epoch = binary.BigEndian.Uint32(frame[75:79])
	b.PoW = binary.BigEndian.Uint32(frame[79:83])
	return b, true
}

func (i InterestPacket) Serialize() []byte {
	frame := make([]byte, interestFrameLen)
	preamble := i.Preamble
	if preamble == ([2]byte{}) {
		preamble = defaultPreamble
	}
	copy(frame[0:2], preamble[:])
	frame[2] = FrameTypeInterest
	copy(frame[3:35], i.DemandCapsule.OID[:])
	binary.BigEndian.PutUint32(frame[35:39], i.DemandCapsule.Nonce)
	copy(frame[39:71], i.DemandCapsule.SaltedPoD[:])
	return frame
}

func ParseInterestPacket(frame []byte) (InterestPacket, bool) {
	var i InterestPacket
	if len(frame) < interestFrameLen {
		return i, false
	}
	if frame[0] != qrofPreamble0 || frame[1] != qrofPreamble1 || frame[2] != FrameTypeInterest {
		return i, false
	}

	i.Preamble = [2]byte{frame[0], frame[1]}
	copy(i.DemandCapsule.OID[:], frame[3:35])
	i.DemandCapsule.Nonce = binary.BigEndian.Uint32(frame[35:39])
	copy(i.DemandCapsule.SaltedPoD[:], frame[39:71])
	return i, true
}
