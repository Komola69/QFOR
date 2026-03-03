package qrof

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"math"
)

const (
	MTU        = 800
	HeaderSize = 64
	// Chunk payload cap keeps data frames safely under typical UDP MTU.
	MaxChunkPayloadSize = 1000

	qrofPreamble0 = 0x51
	qrofPreamble1 = 0x52

	FrameTypeBeacon   = 0xB1
	FrameTypeInterest = 0xA1
	FrameTypeData     = 0xD1

	ProtocolVersion uint8 = 0x02
)

const (
	beaconFrameLen   = 2 + 1 + 32 + 32 + 8 + 4 + 4
	interestFrameLen = 2 + 1 + 1 + 32 + 16 + 2 + 4 + 32
	dataFrameMinLen  = 2 + 1 + 1 + 32 + 16 + 32 + 2 + 2 + 2
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
	Version       uint8
	ChunkIndex    uint16
	ObjectNonce   [16]byte
	DemandCapsule DemandCapsule
}

type DataPacket struct {
	Preamble    [2]byte
	Version     uint8
	OID         [32]byte
	ObjectNonce [16]byte
	PubKey      ed25519.PublicKey
	ChunkIndex  uint16
	TotalChunks uint16
	Signature   []byte
	Payload     []byte
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
	version := i.Version
	if version == 0 {
		version = ProtocolVersion
	}
	frame[3] = version
	copy(frame[4:36], i.DemandCapsule.OID[:])
	copy(frame[36:52], i.ObjectNonce[:])
	binary.BigEndian.PutUint16(frame[52:54], i.ChunkIndex)
	binary.BigEndian.PutUint32(frame[54:58], i.DemandCapsule.Nonce)
	copy(frame[58:90], i.DemandCapsule.SaltedPoD[:])
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
	if frame[3] != ProtocolVersion {
		return i, false
	}

	i.Preamble = [2]byte{frame[0], frame[1]}
	i.Version = frame[3]
	copy(i.DemandCapsule.OID[:], frame[4:36])
	copy(i.ObjectNonce[:], frame[36:52])
	i.ChunkIndex = binary.BigEndian.Uint16(frame[52:54])
	i.DemandCapsule.Nonce = binary.BigEndian.Uint32(frame[54:58])
	copy(i.DemandCapsule.SaltedPoD[:], frame[58:90])
	return i, true
}

func (d DataPacket) Serialize() []byte {
	preamble := d.Preamble
	if preamble == ([2]byte{}) {
		preamble = defaultPreamble
	}

	pub := d.PubKey
	if len(pub) > ed25519.PublicKeySize {
		pub = pub[:ed25519.PublicKeySize]
	}

	payloadLen := len(d.Payload)
	if payloadLen > MaxChunkPayloadSize {
		payloadLen = MaxChunkPayloadSize
	}
	sigLen := len(d.Signature)
	if sigLen > 0xFFFF {
		sigLen = 0xFFFF
	}
	totalChunks := d.TotalChunks
	if totalChunks == 0 {
		totalChunks = 1
	}

	version := d.Version
	if version == 0 {
		version = ProtocolVersion
	}

	frame := make([]byte, 2+1+1+32+16+32+2+2+2+sigLen+2+payloadLen)
	copy(frame[0:2], preamble[:])
	frame[2] = FrameTypeData
	frame[3] = version
	copy(frame[4:36], d.OID[:])
	copy(frame[36:52], d.ObjectNonce[:])
	copy(frame[52:84], pub)
	binary.BigEndian.PutUint16(frame[84:86], d.ChunkIndex)
	binary.BigEndian.PutUint16(frame[86:88], totalChunks)
	binary.BigEndian.PutUint16(frame[88:90], uint16(sigLen))
	copy(frame[90:90+sigLen], d.Signature[:sigLen])
	offset := 90 + sigLen
	binary.BigEndian.PutUint16(frame[offset:offset+2], uint16(payloadLen))
	copy(frame[offset+2:], d.Payload[:payloadLen])
	return frame
}

func ParseDataPacket(frame []byte) (*DataPacket, error) {
	if len(frame) < dataFrameMinLen {
		return nil, errors.New("packet too short")
	}
	if frame[0] != qrofPreamble0 || frame[1] != qrofPreamble1 || frame[2] != FrameTypeData {
		return nil, errors.New("invalid preamble or frame type")
	}
	if frame[3] != ProtocolVersion {
		return nil, errors.New("protocol version mismatch")
	}

	d := &DataPacket{
		Preamble: [2]byte{frame[0], frame[1]},
		Version:  frame[3],
		PubKey:   make(ed25519.PublicKey, ed25519.PublicKeySize),
	}
	copy(d.OID[:], frame[4:36])
	copy(d.ObjectNonce[:], frame[36:52])
	copy(d.PubKey, frame[52:84])
	d.ChunkIndex = binary.BigEndian.Uint16(frame[84:86])
	d.TotalChunks = binary.BigEndian.Uint16(frame[86:88])

	sigLen := int(binary.BigEndian.Uint16(frame[88:90]))
	if len(frame) < 90+sigLen+2 {
		return nil, errors.New("bounds error: signature length exceeds buffer")
	}
	d.Signature = make([]byte, sigLen)
	copy(d.Signature, frame[90:90+sigLen])

	offset := 90 + sigLen
	payloadLen := int(binary.BigEndian.Uint16(frame[offset : offset+2]))
	if payloadLen > MaxChunkPayloadSize {
		return nil, errors.New("bounds error: payload exceeds max chunk size")
	}
	if len(frame) < offset+2+payloadLen {
		return nil, errors.New("bounds error: payload length exceeds buffer")
	}
	d.Payload = make([]byte, payloadLen)
	copy(d.Payload, frame[offset+2:offset+2+payloadLen])

	return d, nil
}
