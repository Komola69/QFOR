package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"qrof/qrof"
)

func main() {
	mode := flag.String("mode", "receiver", "mode: receiver or sender")
	target := flag.String("target", "localhost:9000", "target UDP address (sender mode)")
	difficulty := flag.Uint("difficulty", 0x0FFFFFFF, "PoW admission difficulty")
	flag.Parse()

	switch *mode {
	case "receiver":
		if err := runReceiver(uint32(*difficulty)); err != nil {
			log.Fatalf("receiver failed: %v", err)
		}
	case "sender":
		if err := runSender(*target, uint32(*difficulty)); err != nil {
			log.Fatalf("sender failed: %v", err)
		}
	default:
		log.Fatalf("invalid mode %q (expected receiver or sender)", *mode)
	}
}

func runReceiver(difficulty uint32) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 9000})
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("Listening on 0.0.0.0:9000...")

	gate := qrof.AdmissionGate{
		Difficulty: difficulty,
		QueueSize:  4096,
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	buf := make([]byte, qrof.MTU)
	var pps uint64

	for {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				return err
			}
		} else if n >= qrof.HeaderSize {
			fmt.Printf("Received packet of size: %d\n", n)

			var oid [32]byte
			copy(oid[:], buf[2:34])
			nonce := binary.BigEndian.Uint32(buf[36:40])
			foldedPath := buf[40:qrof.HeaderSize]
			payload := buf[qrof.HeaderSize:n]

			_ = gate.MicroAdmit(oid, nonce)
			_ = gate.InclusionVerify(oid, payload, foldedPath)
			pps++
		} else if n > 0 {
			fmt.Printf("Received packet of size: %d\n", n)
		}

		select {
		case <-ticker.C:
			fmt.Printf("Network PPS: %d\n", pps)
			pps = 0
		default:
		}
	}
}

func runSender(target string, difficulty uint32) error {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	gate := qrof.AdmissionGate{
		Difficulty: difficulty,
		QueueSize:  4096,
	}

	payload := make([]byte, 512)
	foldedPath := make([]byte, qrof.HeaderSize-40)
	var fragmentIdx uint16

	for {
		var oid [32]byte
		mustRead(oid[:])
		mustRead(payload)
		mustRead(foldedPath)

		nonce := findNonce(gate, oid)
		packet := qrof.QROFPacket{
			Preamble:    [2]byte{0x51, 0x52},
			OID:         oid,
			FragmentIdx: fragmentIdx,
			PoWNonce:    nonce,
			MerkleProof: foldedPath,
			Payload:     payload,
		}
		fragmentIdx++

		frame := packet.Serialize()
		if _, err := conn.Write(frame); err != nil {
			return err
		}

		time.Sleep(50 * time.Microsecond)
	}
}

func findNonce(gate qrof.AdmissionGate, oid [32]byte) uint32 {
	var nonce uint32
	for {
		if gate.MicroAdmit(oid, nonce) {
			return nonce
		}
		nonce++
	}
}

func mustRead(dst []byte) {
	if _, err := rand.Read(dst); err != nil {
		panic(err)
	}
}
