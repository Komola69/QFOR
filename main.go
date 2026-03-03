package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"sync/atomic"
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

	buf := make([]byte, 64*1024)
	var pps uint64

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("Network PPS: %d\n", atomic.SwapUint64(&pps, 0))
		}
	}()

	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			continue
		}

		fmt.Printf("Packet Received: %d\n", n)

		var oid [32]byte
		if n > 2 {
			oidEnd := minInt(n, 34)
			copy(oid[:], buf[2:oidEnd])
		}

		var nonce uint32
		if n >= 40 {
			nonce = binary.BigEndian.Uint32(buf[36:40])
		}

		var foldedPath []byte
		if n > 40 {
			pathEnd := minInt(n, qrof.HeaderSize)
			foldedPath = buf[40:pathEnd]
		}

		var payload []byte
		if n > qrof.HeaderSize {
			payload = buf[qrof.HeaderSize:n]
		}

		_ = gate.MicroAdmit(oid, nonce)
		_ = gate.InclusionVerify(oid, payload, foldedPath)
		atomic.AddUint64(&pps, 1)
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
		fmt.Println("Packet Sent")

		time.Sleep(10 * time.Millisecond)
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
