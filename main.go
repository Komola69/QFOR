package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"qrof/qrof"
)

type leafWindow struct {
	mu       sync.RWMutex
	current  [32]byte
	previous [32]byte
}

func main() {
	mode := flag.String("mode", "receiver", "mode: receiver, sender, discover, pull, or promote_test")
	target := flag.String("target", "localhost:9000", "target UDP address")
	targetOID := flag.String("oid", "", "target OID (64 hex chars) for pull/promote_test mode")
	namespaceFlag := flag.String("namespace", "global", "Network isolation scope")
	difficulty := flag.Uint("difficulty", uint(qrof.DifficultyInterest), "PoD difficulty for interests")
	flag.Parse()

	switch *mode {
	case "receiver":
		if err := runReceiver(uint32(*difficulty), *namespaceFlag); err != nil {
			log.Fatalf("receiver failed: %v", err)
		}
	case "sender":
		if err := runSender(*target, uint32(*difficulty), *namespaceFlag); err != nil {
			log.Fatalf("sender failed: %v", err)
		}
	case "discover":
		if err := runDiscover(*target, *namespaceFlag); err != nil {
			log.Fatalf("discover failed: %v", err)
		}
	case "pull":
		if err := runPull(*target, *targetOID, uint32(*difficulty), *namespaceFlag); err != nil {
			log.Fatalf("pull failed: %v", err)
		}
	case "promote_test":
		if err := runPromoteTest(*target, *targetOID, uint32(*difficulty), *namespaceFlag); err != nil {
			log.Fatalf("promote_test failed: %v", err)
		}
	default:
		log.Fatalf("invalid mode %q (expected receiver, sender, discover, pull, or promote_test)", *mode)
	}
}

func runReceiver(difficulty uint32, namespace string) error {
	listenConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 9000})
	if err != nil {
		return err
	}
	defer listenConn.Close()
	fmt.Println("Receiver listening on 0.0.0.0:9000...")

	broadcastConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4bcast, Port: 9000})
	if err != nil {
		return err
	}
	defer broadcastConn.Close()

	gradients := qrof.NewGradientTable()
	nsHash := qrof.DeriveNamespace(namespace)
	pub, priv, err := qrof.LoadOrGenerateIdentity("receiver_identity.key")
	if err != nil {
		return fmt.Errorf("load/generate receiver identity: %w", err)
	}

	var serviceNonce [16]byte
	mustRead(serviceNonce[:])
	authenticOID := qrof.DeriveOID(pub, serviceNonce)

	fmt.Printf("Receiver Authentic OID: %x\n", authenticOID)
	var salts leafWindow

	var pps uint64
	var verifiedPackets uint64
	var totalVerifyNS int64

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			netPPS := atomic.SwapUint64(&pps, 0)
			verified := atomic.SwapUint64(&verifiedPackets, 0)
			verifyNS := atomic.SwapInt64(&totalVerifyNS, 0)

			var eer float64
			if verifyNS > 0 {
				eer = float64(verified) / (float64(verifyNS) / float64(time.Second))
			}
			fmt.Printf("Network PPS: %d | EER: %.2f\n", netPPS, eer)
		}
	}()

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			var leaf [32]byte
			mustRead(leaf[:])
			beacon := qrof.Beacon{
				Version:     qrof.ProtocolVersion,
				OID:         authenticOID,
				ObjectNonce: serviceNonce,
				LeafHash:    leaf,
				Potential:   0.5,
				Epoch:       uint32(time.Now().Unix()),
			}
			beacon.PoW = qrof.SolveBeaconPoW(beacon, qrof.DifficultyInterest)
			rotateSaltWindow(&salts, beacon.LeafHash)
			gradients.AddPendingInterest(beacon.OID)

			payload := addNamespacePrefix(nsHash, beacon.Serialize())
			if _, err := broadcastConn.Write(payload); err != nil {
				fmt.Printf("Beacon broadcast failed: %v\n", err)
			} else {
				fmt.Printf("Beacon Broadcast: epoch=%d oid=%x\n", beacon.Epoch, beacon.OID[:4])
			}

			<-ticker.C
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			continue
		}
		if n < len(nsHash) {
			continue
		}
		if !bytes.Equal(buf[:len(nsHash)], nsHash[:]) {
			continue
		}

		frame := buf[len(nsHash):n]
		if len(frame) == 0 {
			continue
		}
		atomic.AddUint64(&pps, 1)

		if interest, ok := qrof.ParseInterestPacket(frame); ok {
			oid := interest.DemandCapsule.OID
			inPIT := gradients.HasPendingInterest(oid)
			inDormant := gradients.HasDormant(oid)

			if !inPIT && !inDormant {
				// Silently drop non-admitted interests.
				continue
			}

			// Verify Object-routed identity: OID must match pubkey + objectNonce from interest
			// and must match our stable service object instance.
			if interest.ObjectNonce != serviceNonce {
				continue
			}
			computedOID := qrof.DeriveOID(pub, interest.ObjectNonce)
			if computedOID != oid {
				// We don't own this object instance
				continue
			}

			start := time.Now()
			currentLeaf, previousLeaf := snapshotSaltWindow(&salts)
			currentSalt := qrof.DeriveSalt(currentLeaf, oid)
			previousSalt := qrof.DeriveSalt(previousLeaf, oid)

			// TotalChunks is always 1 for single-chunk objects in this receiver response logic
			valid := qrof.VerifyA_PoDWithDifficulty(interest.DemandCapsule, interest.ChunkIndex, 1, currentSalt, difficulty) ||
				qrof.VerifyA_PoDWithDifficulty(interest.DemandCapsule, interest.ChunkIndex, 1, previousSalt, difficulty)
			if !valid && inDormant {
				if dormantLeaf, ok := gradients.DormantLeafHash(oid); ok {
					dormantSalt := qrof.DeriveSalt(dormantLeaf, oid)
					valid = qrof.VerifyA_PoDWithDifficulty(interest.DemandCapsule, interest.ChunkIndex, 1, dormantSalt, difficulty)
				}
			}
			atomic.AddInt64(&totalVerifyNS, time.Since(start).Nanoseconds())

			if valid {
				atomic.AddUint64(&verifiedPackets, 1)
				if inDormant {
					gradients.PromoteDormant(oid)
				}
				gradients.UpdateGradient(oid, 0.1)
				if inPIT {
					gradients.RemovePendingInterest(oid)
				}
				payload := []byte("Hello from Windows")
				fmt.Println("[DEBUG] Preparing Data response")
				msg := qrof.BuildDataSigningMessage(qrof.ProtocolVersion, oid, 0, 1, payload)
				sig := qrof.SignData(priv, msg)
				fmt.Println("[DEBUG] Data signed, calling CraftDataPacket")
				data := qrof.CraftDataPacket(qrof.ProtocolVersion, oid, interest.ObjectNonce, pub, sig, payload)
				if _, err := listenConn.WriteToUDP(addNamespacePrefix(nsHash, data), addr); err != nil {
					fmt.Printf("Data send failed to %s: %v\n", addr.String(), err)
				}
				fmt.Printf("[DEBUG] Data sent, Interest Verified from %s\n", addr.String())
				continue
			}

			fmt.Printf("Interest Rejected from %s\n", addr.String())
			continue
		}

		if beacon, ok := qrof.ParseBeacon(frame); ok {
			// Split beacon handling into solicited (PIT-matching) and
			// unsolicited discovery traffic.
			if gradients.HasPendingInterest(beacon.OID) {
				continue
			}
			if qrof.VerifyDiscoveryPoW(beacon) {
				gradients.AddDormant(beacon.OID, beacon.LeafHash)
				fmt.Printf("[DISCOVERY] Dormant OID accepted: %x\n", beacon.OID[:4])
			}
			continue
		}

		fmt.Printf("Packet Received: %d bytes from %s\n", n, addr.String())
	}
}

func runSender(target string, difficulty uint32, namespace string) error {
	listenConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 9000})
	if err != nil {
		return err
	}
	defer listenConn.Close()
	fmt.Println("Sender listening for beacons on 0.0.0.0:9000...")

	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	sendConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return err
	}
	defer sendConn.Close()

	gradients := qrof.NewGradientTable()
	nsHash := qrof.DeriveNamespace(namespace)
	buf := make([]byte, 64*1024)
	var namespaceDrop uint64
	var namespaceAccept uint64

	for {
		n, _, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			continue
		}
		if n < len(nsHash) {
			namespaceDrop++
			fmt.Printf("[INGRESS] Alien beacon dropped. Drops: %d\n", namespaceDrop)
			continue
		}
		if !bytes.Equal(buf[:len(nsHash)], nsHash[:]) {
			namespaceDrop++
			fmt.Printf("[INGRESS] Alien beacon dropped. Drops: %d\n", namespaceDrop)
			continue
		}
		namespaceAccept++
		fmt.Printf("[INGRESS] Valid beacon accepted. Accepts: %d\n", namespaceAccept)

		beacon, ok := qrof.ParseBeacon(buf[len(nsHash):n])
		if !ok {
			continue
		}

		gradients.AddPendingInterest(beacon.OID)
		if !gradients.VerifyBeaconIfDemanded(beacon, func(b qrof.Beacon) bool {
			return qrof.VerifyBeaconPoW(b, qrof.DifficultyInterest)
		}) {
			fmt.Println("Beacon failed demand-triggered verification")
			continue
		}

		salt := qrof.DeriveSalt(beacon.LeafHash, beacon.OID)

		capsule := qrof.SolveA_PoD(beacon.OID, 0, 1, salt, difficulty)

		interest := qrof.InterestPacket{
			Version:     qrof.ProtocolVersion,
			ChunkIndex:  0,
			ObjectNonce: beacon.ObjectNonce,
			DemandCapsule: capsule,
		}

		if _, err := sendConn.Write(addNamespacePrefix(nsHash, interest.Serialize())); err != nil {
			return err
		}

		gradients.RemovePendingInterest(beacon.OID)
		fmt.Println("Packet Sent")
		time.Sleep(10 * time.Millisecond)
	}
}

func runDiscover(target string, namespace string) error {
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}

	sendConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return err
	}
	defer sendConn.Close()
	nsHash := qrof.DeriveNamespace(namespace)

	for {
		beacon := randomBeacon()
		beacon.PoW = qrof.SolveBeaconPoW(beacon, qrof.DifficultyDiscovery)

		if _, err := sendConn.Write(addNamespacePrefix(nsHash, beacon.Serialize())); err != nil {
			return err
		}
		fmt.Printf("Discovery Beacon Sent: oid=%x pow=%d\n", beacon.OID, beacon.PoW)
		time.Sleep(5 * time.Second)
	}
}

func runPull(target string, oidHex string, difficulty uint32, namespace string) error {
	targetOID, err := parseOIDHex(oidHex)
	if err != nil {
		return err
	}
	nsHash := qrof.DeriveNamespace(namespace)

	listenConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 9000})
	if err != nil {
		return err
	}
	defer listenConn.Close()

	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	sendConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return err
	}
	defer sendConn.Close()

	fmt.Printf("Pull waiting for beacon OID=%x\n", targetOID)
	buf := make([]byte, 64*1024)

	for {
		n, _, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			continue
		}
		if n < len(nsHash) {
			continue
		}
		if !bytes.Equal(buf[:len(nsHash)], nsHash[:]) {
			continue
		}

		beacon, ok := qrof.ParseBeacon(buf[len(nsHash):n])
		if !ok || beacon.OID != targetOID {
			continue
		}
		if !qrof.VerifyDiscoveryPoW(beacon) && !qrof.VerifyBeaconPoW(beacon, qrof.DifficultyInterest) {
			continue
		}

		salt := qrof.DeriveSalt(beacon.LeafHash, targetOID)
		capsule := qrof.SolveA_PoD(targetOID, 0, 1, salt, difficulty)

		interest := qrof.InterestPacket{
			Version:     qrof.ProtocolVersion,
			ChunkIndex:  0,
			ObjectNonce: beacon.ObjectNonce,
			DemandCapsule: capsule,
		}

		if _, err := sendConn.Write(addNamespacePrefix(nsHash, interest.Serialize())); err != nil {
			return err
		}
		fmt.Printf("Pull Interest Sent: oid=%x nonce=%d\n", targetOID[:4], capsule.Nonce)
		return nil
	}
}

func runPromoteTest(target string, oidHex string, difficulty uint32, namespace string) error {
	targetOID, err := parseOIDHex(oidHex)
	if err != nil {
		return err
	}

	listenConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 9000})
	if err != nil {
		return err
	}
	defer listenConn.Close()

	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}

	sendConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return err
	}
	defer sendConn.Close()
	nsHash := qrof.DeriveNamespace(namespace)

	if err := listenConn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	fmt.Printf("[SYNC] Waiting for beacon OID=%x\n", targetOID)

	buf := make([]byte, 64*1024)
	var beacon qrof.Beacon
	for {
		n, _, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("beacon sync failed: %w", err)
		}
		if n <= 0 || n < len(nsHash) {
			continue
		}
		if !bytes.Equal(buf[:len(nsHash)], nsHash[:]) {
			continue
		}

		parsed, ok := qrof.ParseBeacon(buf[len(nsHash):n])
		if !ok {
			continue
		}
		if parsed.OID != targetOID {
			continue
		}
		if !qrof.VerifyBeaconPoW(parsed, qrof.DifficultyInterest) {
			continue
		}
		beacon = parsed
		fmt.Printf("[SYNC] Captured beacon for OID, LeafHash: %x\n", beacon.LeafHash[:4])
		break
	}

	salt := qrof.DeriveSalt(beacon.LeafHash, targetOID)
	capsule := qrof.SolveA_PoD(targetOID, 0, 1, salt, difficulty)

	interest := qrof.InterestPacket{
		Version:     qrof.ProtocolVersion,
		ChunkIndex:  0,
		ObjectNonce: beacon.ObjectNonce,
		DemandCapsule: capsule,
	}

	if _, err := sendConn.Write(addNamespacePrefix(nsHash, interest.Serialize())); err != nil {
		return err
	}
	fmt.Printf("PromoteTest Interest Sent: oid=%x nonce=%d\n", targetOID[:4], capsule.Nonce)

	if err := sendConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	for {
		n, err := sendConn.Read(buf)
		if err != nil {
			return fmt.Errorf("data read timeout/failed: %w", err)
		}
		if n < len(nsHash) {
			continue
		}
		if !bytes.Equal(buf[:len(nsHash)], nsHash[:]) {
			continue
		}

		frame := buf[len(nsHash):n]
		if _, ok := qrof.ParseBeacon(frame); ok {
			// Ignore periodic receiver broadcasts while waiting for data.
			continue
		}

		data, err := qrof.ParseDataPacket(frame)
		if err != nil {
			continue
		}

		if data.OID != targetOID {
			return fmt.Errorf("identity mismatch: response oid=%x expected=%x", data.OID[:4], targetOID[:4])
		}
		// In v1.1 we verify OID = Hash(pubkey || objectNonce)
		derived := qrof.DeriveOID(data.PubKey, data.ObjectNonce)
		if derived != data.OID {
			return fmt.Errorf("identity mismatch: oid does not match pubkey+nonce hash")
		}
		msg := qrof.BuildDataSigningMessage(data.Version, data.OID, data.ChunkIndex, data.TotalChunks, data.Payload)
		if !qrof.VerifySignature(data.PubKey, msg, data.Signature) {
			return fmt.Errorf("invalid signature")
		}
		fmt.Printf("[SECURE] Authentic Data Received: %s\n", string(data.Payload))
		return nil
	}
}

func randomBeacon() qrof.Beacon {
	var oid [32]byte
	var nonce [16]byte
	var leaf [32]byte
	mustRead(oid[:])
	mustRead(nonce[:])
	mustRead(leaf[:])

	return qrof.Beacon{
		Version:     qrof.ProtocolVersion,
		OID:         oid,
		ObjectNonce: nonce,
		LeafHash:    leaf,
		Potential:   0.5,
		Epoch:       uint32(time.Now().Unix()),
	}
}

func rotateSaltWindow(w *leafWindow, leaf [32]byte) {
	w.mu.Lock()
	w.previous = w.current
	w.current = leaf
	w.mu.Unlock()
}

func snapshotSaltWindow(w *leafWindow) ([32]byte, [32]byte) {
	w.mu.RLock()
	current := w.current
	previous := w.previous
	w.mu.RUnlock()
	return current, previous
}

func mustRead(dst []byte) {
	if _, err := rand.Read(dst); err != nil {
		panic(err)
	}
}

func parseOIDHex(input string) ([32]byte, error) {
	var oid [32]byte

	s := strings.TrimSpace(input)
	if s == "" {
		return oid, fmt.Errorf("missing -oid (expected 64 hex chars)")
	}

	raw, err := hex.DecodeString(s)
	if err != nil {
		return oid, fmt.Errorf("invalid -oid hex: %w", err)
	}
	if len(raw) != 32 {
		return oid, fmt.Errorf("invalid -oid length: got %d bytes, expected 32", len(raw))
	}

	copy(oid[:], raw)
	return oid, nil
}

func addNamespacePrefix(nsHash [32]byte, payload []byte) []byte {
	out := make([]byte, len(nsHash)+len(payload))
	copy(out, nsHash[:])
	copy(out[len(nsHash):], payload)
	return out
}
