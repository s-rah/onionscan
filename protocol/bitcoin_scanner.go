package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

type BitcoinProtocolScanner struct {
}

// Message start of packets on mainnet
var MsgStartMainnet = []byte{0xf9, 0xbe, 0xb4, 0xd9}

// User agent to send to scanned nodes
const user_agent = "/OnionScan:0.0.1/"

// Protocol version to send to scanned nodes
const protocol_version uint32 = 70014

// Bitcoin protocol port
const PORT int = 8333

// Maximum length of user agent
const MAX_SUBVERSION_LENGTH = 256

// Maximum payload length of packet we expect to receive
const MAX_PACKET_LENGTH = 1000*30 + 3

// Maximum number of addresses in addr packet
const MAX_ADDR = 1000

// Message types
const MSG_VERSION = "version"
const MSG_VERACK = "verack"
const MSG_GETADDR = "getaddr"
const MSG_ADDR = "addr"
const MSG_PING = "ping"
const MSG_PONG = "pong"
const MSG_FEEFILTER = "feefilter"

// P2P-encoded onion addresses start with this prefix
var AddrStartOnion = []byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43}

// Header (https://bitcoin.org/en/developer-reference#message-headers)
//   0  4b       msgstart
//   4  12b      type
//   16 uint32   payload length
//   20 4b       checksum

// Version packet (https://bitcoin.org/en/developer-reference#version)
//   0     uint32   Protocol version
//   4     uint64   Node services
//   12    uint64   Node timestamp
//   20    uint64   Receiving node services
//   28    16b      Receiving node address
//   44    uint16   Receiving node port
//   46    uint64   Sending node services
//   54    16b      Sending node address
//   70    uint16   Sending node port
//   72    8b       Nonce
//   80    x  <compactsize> <User agent>
//   80+x  uint32   Block start height
//   84+x  uint8    Relay flag

type Packet struct {
	msgtype string
	payload []byte
}

// Bitcoin 256-bit hash
func Hash256(payload []byte) [32]byte {
	h1 := sha256.Sum256(payload)
	return sha256.Sum256(h1[:])
}

// Bitcoin P2P packet checksum
func Checksum(payload []byte) []byte {
	hash := Hash256(payload)
	return hash[0:4]
}

// Read "compact size" varint.
// Return value and size of value read. The latter will be 0 on error,
// which happens if there was not enough space to read it.
func ReadCompactSize(input []byte) (uint64, int) {
	if len(input) < 1 {
		return 0, 0
	}
	if input[0] <= 252 {
		return uint64(input[0]), 1
	} else if input[0] == 253 && len(input) >= 3 {
		return uint64(binary.LittleEndian.Uint16(input[1:3])), 3
	} else if input[0] == 254 && len(input) >= 5 {
		return uint64(binary.LittleEndian.Uint32(input[1:5])), 5
	} else if input[0] == 255 && len(input) >= 9 {
		return uint64(binary.LittleEndian.Uint64(input[1:9])), 9
	}
	return 0, 0
}

// Simple utility function to get zero-terminated string
func cstring(n []byte) string {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return string(n[:i])
		}
	}
	return string(n)
}

// Send P2P packet to connection
func SendPacket(conn net.Conn, pkt *Packet) error {
	hdr := make([]byte, 24, 24)
	copy(hdr[0:4], MsgStartMainnet)
	copy(hdr[4:16], pkt.msgtype)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(pkt.payload)))
	copy(hdr[20:24], Checksum(pkt.payload))

	n, err := conn.Write(hdr)
	if err != nil || n != len(hdr) {
		return fmt.Errorf("Could not send P2P packet header: %s", err)
	}
	n, err = conn.Write(pkt.payload)
	if err != nil || n != len(pkt.payload) {
		return fmt.Errorf("Could not send P2P packet data: %s", err)
	}
	return nil
}

// Receive P2P packet from connection
func ReceivePacket(conn net.Conn) (*Packet, error) {
	var pkt Packet
	hdr := make([]byte, 24, 24)
	_, err := io.ReadFull(conn, hdr)

	if err != nil {
		return nil, fmt.Errorf("Could not read P2P packet header: %s", err)
	}
	if !bytes.Equal(hdr[0:4], MsgStartMainnet) {
		return nil, fmt.Errorf("P2P packet started with %q instead of %q", hdr[0:4], MsgStartMainnet)
	}
	pkt.msgtype = cstring(hdr[4:16])
	length := binary.LittleEndian.Uint32(hdr[16:20])
	if length > MAX_PACKET_LENGTH {
		return nil, fmt.Errorf("Packet too long (%d)", length)
	}

	pkt.payload = make([]byte, length, length)
	_, err = io.ReadFull(conn, pkt.payload)
	if err != nil {
		return nil, fmt.Errorf("Could not read Bitcoin P2P packet payload: %s", err)
	}

	if !bytes.Equal(hdr[20:24], Checksum(pkt.payload)) {
		return nil, fmt.Errorf("P2P packet checksum mismatch")
	}
	return &pkt, nil
}

// Encode .onion address into 16-byte "IPv6" address used by Bitcoin P2P
func EncodeOnion(onion string) ([]byte, error) {
	r := regexp.MustCompile(`(\.|^)([a-z0-7]{16})\.onion$`)
	onion_base := r.FindStringSubmatch(onion)
	if onion_base == nil {
		return nil, fmt.Errorf("Not a valid onion address %s", onion)
	}

	onion_enc, err := base32.StdEncoding.DecodeString(strings.ToUpper(onion_base[2]))
	if err != nil {
		return nil, fmt.Errorf("Error in Base32 decoding of onion %s: %s", onion_base, err)
	}
	theiraddr := make([]byte, 16, 16)
	copy(theiraddr, AddrStartOnion)
	copy(theiraddr[len(AddrStartOnion):], onion_enc)
	return theiraddr, nil
}

// Extract .onion from 16-byte "IPv6" address used by Bitcoin P2P
func DecodeOnion(addr []byte) (string, error) {
	if bytes.Equal(addr[0:len(AddrStartOnion)], AddrStartOnion) {
		return strings.ToLower(base32.StdEncoding.EncodeToString(addr[len(AddrStartOnion):])) + ".onion", nil
	}
	return "", fmt.Errorf("Not an onion address")
}

// Build and send version message
func SendVersion(conn net.Conn, osc *config.OnionScanConfig, hiddenService string) error {
	// Most fields can be left at zero
	payload := make([]byte, 80, 80) // static part of payload
	tail := make([]byte, 5, 5)      // last five bytes
	binary.LittleEndian.PutUint32(payload[0:4], protocol_version)
	binary.LittleEndian.PutUint64(payload[12:20], uint64(time.Now().Unix()))

	theiraddr, err := EncodeOnion(hiddenService)
	if err != nil {
		return err
	}
	copy(payload[28:28+16], theiraddr)
	binary.BigEndian.PutUint16(payload[44:46], uint16(PORT))

	payload = append(payload, uint8(len(user_agent)))
	payload = append(payload, user_agent...)
	payload = append(payload, tail...)

	return SendPacket(conn, &Packet{MSG_VERSION, payload})
}

// Handle incoming version message, and parse message payload into report
func HandleVersion(conn net.Conn, osc *config.OnionScanConfig, report *report.OnionScanReport, pkt *Packet) error {
	report.BitcoinProtocolVersion = int(binary.LittleEndian.Uint32(pkt.payload[0:4]))
	user_agent_length, sizesize := ReadCompactSize(pkt.payload[80:])
	if sizesize != 0 && user_agent_length < MAX_SUBVERSION_LENGTH {
		report.BitcoinUserAgent = string(pkt.payload[81 : 81+user_agent_length])
	} else {
		return fmt.Errorf("User agent string too long")
	}
	osc.LogInfo(fmt.Sprintf("Found Bitcoin version: %s (%d)", report.BitcoinUserAgent, report.BitcoinProtocolVersion))
	return nil
}

// Handle incoming verack message
func HandleVerAck(conn net.Conn, osc *config.OnionScanConfig, report *report.OnionScanReport, pkt *Packet) error {
	// This message has no content. However when receiving this message the
	// version negotiation has been completed, and that other queries can be sent.
	osc.LogInfo(fmt.Sprintf("Sending getaddr message"))
	return SendPacket(conn, &Packet{MSG_GETADDR, []byte{}})
}

// Handle incoming ping message
func HandlePing(conn net.Conn, osc *config.OnionScanConfig, report *report.OnionScanReport, pkt *Packet) error {
	if len(pkt.payload) >= 8 { // Ping message with nonce, peer expects a pong
		return SendPacket(conn, &Packet{MSG_PONG, pkt.payload[0:8]})
	}
	return nil
}

// Handle incoming addr message, and parse message payload into report
func HandleAddr(conn net.Conn, osc *config.OnionScanConfig, report *report.OnionScanReport, pkt *Packet) error {
	numaddr, sizesize := ReadCompactSize(pkt.payload)
	if sizesize == 0 || numaddr > MAX_ADDR {
		return fmt.Errorf("Invalid number of addresses")
	}
	// Parse addresses. We're only interested in .onions
	osc.LogInfo(fmt.Sprintf("Processing addr message with %d entries", numaddr))
	ptr := sizesize
	for i := 0; i < int(numaddr); i++ {
		if ptr+30 > len(pkt.payload) {
			return fmt.Errorf("Invalid addr packet")
		}
		onion, err := DecodeOnion(pkt.payload[ptr+12 : ptr+12+16])
		if err == nil {
			port := binary.BigEndian.Uint16(pkt.payload[ptr+28 : ptr+30])
			spec := fmt.Sprintf("%s:%d", onion, port)
			osc.LogInfo(fmt.Sprintf("Found onion peer: %s", spec))
			report.BitcoinOnionPeers = append(report.BitcoinOnionPeers, spec)
		}
		ptr += 30
	}
	return nil
}

// Receive messages and handle them
func MessageLoop(conn net.Conn, osc *config.OnionScanConfig, report *report.OnionScanReport) error {
	addrCount := 0
	for {
		pkt, err := ReceivePacket(conn)
		if err != nil {
			return fmt.Errorf("Error receiving P2P packet: %s", err)
		}
		switch pkt.msgtype {
		case MSG_VERSION:
			err = HandleVersion(conn, osc, report, pkt)
			if err != nil {
				return fmt.Errorf("Error handling version message: %s", err)
			}
		case MSG_VERACK:
			err = HandleVerAck(conn, osc, report, pkt)
			if err != nil {
				return fmt.Errorf("Error handling verack message: %s", err)
			}
		case MSG_PING:
			err = HandlePing(conn, osc, report, pkt)
			if err != nil {
				return fmt.Errorf("Error handling ping message: %s", err)
			}
		case MSG_ADDR:
			err = HandleAddr(conn, osc, report, pkt)
			if err != nil {
				return fmt.Errorf("Error handling addr message: %s", err)
			}
			addrCount += 1
			if addrCount == 2 { // Second address message should trigger exit from loop, collected all the info needed
				return nil
			}
		case MSG_FEEFILTER:
			// Ignore
		default:
			osc.LogInfo(fmt.Sprintf("Unexpected message %q", pkt.msgtype))
		}
	}
	return nil
}

func (rps *BitcoinProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionScanConfig, report *report.OnionScanReport) {
	// Bitcoin
	osc.LogInfo(fmt.Sprintf("Checking %s Bitcoin(%d)\n", hiddenService, PORT))
	conn, err := utils.GetNetworkConnection(hiddenService, PORT, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo(fmt.Sprintf("Failed to connect to service on port %d\n", PORT))
		report.BitcoinDetected = false
	} else {
		osc.LogInfo("Detected possible Bitcoin instance\n")
		report.BitcoinDetected = true

		conn.SetDeadline(time.Now().Add(30 * time.Second)) // Allow it to take 30 seconds at most
		err = SendVersion(conn, osc, hiddenService)
		if err == nil {
			err = MessageLoop(conn, osc, report)
			if err != nil {
				osc.LogInfo(fmt.Sprintf("Error in receive loop: %s", err))
			}
		} else {
			osc.LogInfo(fmt.Sprintf("Error sending to Bitcoin node: %s\n", err))
		}
	}
	if conn != nil {
		conn.Close()
	}
}
