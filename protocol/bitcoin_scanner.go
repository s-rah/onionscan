package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"io"
	"net"
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

// Maximum length of user agent
const MAX_SUBVERSION_LENGTH = 256

// Message types
const MSG_VERSION = "version"

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

// Simple utility function to get zero-terminated string
func cstring(n []byte) string {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return string(n[:i])
		}
	}
	return string(n)
}

func SendVersion(conn net.Conn, osc *config.OnionscanConfig) error {
	// Build version message
	// Most fields can be left at zero
	payload := make([]byte, 80, 80) // static part of payload
	tail := make([]byte, 5, 5)      // last five bytes
	binary.LittleEndian.PutUint32(payload[0:4], protocol_version)
	binary.LittleEndian.PutUint64(payload[12:20], uint64(time.Now().Unix()))

	payload = append(payload, uint8(len(user_agent)))
	payload = append(payload, user_agent...)
	payload = append(payload, tail...)

	// Build Bitcoin P2P packet header
	hdr := make([]byte, 24, 24)
	copy(hdr[0:4], MsgStartMainnet)
	copy(hdr[4:16], MSG_VERSION)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(payload)))
	copy(hdr[20:24], Checksum(payload))

	n, err := conn.Write(hdr)
	if err != nil || n != len(hdr) {
		return fmt.Errorf("Could not send P2P packet header: %s", err)
	}
	n, err = conn.Write(payload)
	if err != nil || n != len(payload) {
		return fmt.Errorf("Could not send P2P packet data: %s", err)
	}
	return nil
}

func ReceiveVersion(conn net.Conn, osc *config.OnionscanConfig, report *report.OnionScanReport) error {
	hdr := make([]byte, 24, 24)
	_, err := io.ReadFull(conn, hdr)

	if err != nil {
		return fmt.Errorf("Could not read P2P packet header: %s", err)
	}
	if !bytes.Equal(hdr[0:4], MsgStartMainnet) {
		return fmt.Errorf("P2P packet started with %q instead of %q", hdr[0:4], MsgStartMainnet)
	}
	msgtype_s := cstring(hdr[4:16])
	if msgtype_s != MSG_VERSION {
		return fmt.Errorf("P2P packet was not \"version\" as expected but %q", msgtype_s)
	}
	length := binary.LittleEndian.Uint32(hdr[16:20])
	if length > (80 + 2 + MAX_SUBVERSION_LENGTH + 5) { // Maximum possible version packet payload
		return fmt.Errorf("Version packet too long (%d)", length)
	}

	payload := make([]byte, length, length)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		return fmt.Errorf("Could not read Bitcoin P2P packet payload: %s", err)
	}

	if !bytes.Equal(hdr[20:24], Checksum(payload)) {
		return fmt.Errorf("P2P packet checksum mismatch")
	}

	// Parse information from version message payload into report
	report.BitcoinProtocolVersion = int(binary.LittleEndian.Uint32(payload[0:4]))
	user_agent_length := payload[80]
	// Only one-byte CompactSizes for now, this string can be 256 bytes max anyway and it's hardly ever longer than 100
	if user_agent_length < 253 {
		report.BitcoinUserAgent = string(payload[81 : 81+user_agent_length])
	} else {
		return fmt.Errorf("User agent string too long")
	}
	osc.LogInfo(fmt.Sprintf("Found Bitcoin version: %s (%d)", report.BitcoinUserAgent, report.BitcoinProtocolVersion))
	return nil
}

func (rps *BitcoinProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionscanConfig, report *report.OnionScanReport) {
	// Bitcoin
	osc.LogInfo(fmt.Sprintf("Checking %s Bitcoin(8333)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 8333, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 8333\n")
		report.BitcoinDetected = false
	} else {
		osc.LogInfo("Detected possible Bitcoin instance\n")
		report.BitcoinDetected = true

		err = SendVersion(conn, osc)
		if err == nil {
			err = ReceiveVersion(conn, osc, report)
			if err != nil {
				osc.LogInfo(fmt.Sprintf("Error reading from Bitcoin node: %s\n", err))
			}
		} else {
			osc.LogInfo(fmt.Sprintf("Error sending to Bitcoin node: %s\n", err))
		}
	}
	if conn != nil {
		conn.Close()
	}
}
