package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
)

// Single-threaded SOCKS5 server for testing.
// Instead of making outgoing connections it calls an interface, that has to be provided on creation,
// to handle the connections further.
type TestSOCKS5Server struct {
	ListenAddress string
	t             *testing.T
	listener      net.Listener
	handler       IncomingConnectionHandler
	waitExit      chan bool
}

// This interface is passed to SOCKS5Server to handle incoming connections
type IncomingConnectionHandler interface {
	// Check if connection succeeds. Returns false if connection
	// refused, true if connection accepted.
	ConnectionSucceeds(domainname string, port uint16) bool
	// This is called when the connection succeeds, to handle further processing
	HandleConnection(domainname string, port uint16, conn net.Conn)
}

// SOCKS5 protocol constants
const (
	SocksAuth_NONE = 0x00
)
const (
	SocksCommand_CONNECT = 0x01
)
const (
	SocksAddressType_IPV4       = 0x01
	SocksAddressType_DOMAINNAME = 0x03
	SocksAddressType_IPV6       = 0x04
)

const (
	SocksResponse_SUCCEEDED          = 0x00
	SocksResponse_CONNECTION_REFUSED = 0x05
)

// Handle incoming SOCKS5 connection (protocol described in https://www.ietf.org/rfc/rfc1928.txt)
func (os *TestSOCKS5Server) handleConnection(conn net.Conn) {
	var err error
	recvbuf := make([]byte, 4096)
	defer conn.Close()
	// Handle incoming connection request
	// Version byte
	_, err = io.ReadFull(conn, recvbuf[0:1])
	if err != nil {
		os.t.Errorf("Network read error reading version byte: %s", err)
		return
	}
	if recvbuf[0] != 0x05 {
		os.t.Errorf("Invalid socks version: 0x%02x", recvbuf[0])
		return
	}
	// Receive authentication methods, prefixed by 1-byte length
	_, err = io.ReadFull(conn, recvbuf[0:1])
	if err != nil {
		os.t.Errorf("Network read error while reading authentication method count: %s", err)
		return
	}
	nmethods := recvbuf[0]
	_, err = io.ReadFull(conn, recvbuf[0:nmethods])
	if err != nil {
		os.t.Errorf("Network read error while reading authentication methods: %s", err)
		return
	}
	// We expect authentication method "none" only
	if nmethods > 1 || recvbuf[0] != SocksAuth_NONE {
		os.t.Errorf("Unexpected authentication methods: %v", recvbuf)
		return
	}
	// Send response
	var authresponse = []byte{0x05, SocksAuth_NONE}
	var n int
	n, err = conn.Write(authresponse)
	if err != nil || n != len(authresponse) {
		os.t.Errorf("Could not send authentication response: %s", err)
		return
	}
	// Should handle authentication response here for authentication method != 0x00
	// As only no-authentication is supported, skip that.
	// Handle connection request: reads (version, command, reserved, address_type)
	_, err = io.ReadFull(conn, recvbuf[0:4])
	if err != nil {
		os.t.Errorf("Network read error while reading connection request: %s", err)
		return
	}
	if recvbuf[0] != 0x05 {
		os.t.Errorf("Invalid SOCKS version: 0x%02x", recvbuf[0])
		return
	}
	if recvbuf[1] != SocksCommand_CONNECT {
		os.t.Errorf("Unhandled SOCKS5 command: 0x%02x", recvbuf[1])
		return
	}
	if recvbuf[3] != SocksAddressType_DOMAINNAME {
		os.t.Errorf("Unhandled SOCKS5 address type: 0x%02x", recvbuf[3])
		return
	}
	// When we end up here, we've received a domainname connection request
	// Receive domain name length
	_, err = io.ReadFull(conn, recvbuf[0:1])
	if err != nil {
		os.t.Errorf("Error receiving domain name length: %s", err)
		return
	}
	// Receive domain name and port
	namelength := recvbuf[0]
	_, err = io.ReadFull(conn, recvbuf[0:namelength+2])
	if err != nil {
		os.t.Errorf("Error receiving domain name: %s", err)
		return
	}
	name := string(recvbuf[0:namelength])
	port := binary.BigEndian.Uint16(recvbuf[namelength : namelength+2])
	// Send response according to test result
	var resp byte
	if os.handler.ConnectionSucceeds(name, port) {
		resp = SocksResponse_SUCCEEDED
	} else {
		resp = SocksResponse_CONNECTION_REFUSED
	}
	var connresponse = []byte{0x05, resp, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	n, err = conn.Write(connresponse)
	if err != nil || n != len(connresponse) {
		os.t.Errorf("Could not send connection response: %s", err)
		return
	}
	if resp == SocksResponse_SUCCEEDED {
		os.handler.HandleConnection(name, port, conn)
	}
}

// Listen for connections. This be called in a goroutine.
func (os *TestSOCKS5Server) listen() {
	for {
		conn, err := os.listener.Accept()
		if err != nil {
			os.waitExit <- true
			return
		}
		os.handleConnection(conn)
	}
}

// Start the SOCKS5 server
func (os *TestSOCKS5Server) Start() {
	go os.listen()
}

// Stop the SOCKS5 server
func (os *TestSOCKS5Server) Stop() {
	os.listener.Close()
	<-os.waitExit
}

// Create a new SOCKS5 test server
func NewTestSOCKS5Server(t *testing.T, handler IncomingConnectionHandler) (*TestSOCKS5Server, error) {
	listenPort := 12345 // Arbitrary, could be dynamic/random
	listenAddress := fmt.Sprintf("127.0.0.1:%d", listenPort)

	l, err := net.Listen("tcp", listenAddress)
	if err != nil {
		t.Errorf("Error listening SOCKS5 server on %s: %s", listenAddress, err)
		return nil, err
	}
	os := new(TestSOCKS5Server)
	os.ListenAddress = listenAddress
	os.listener = l
	os.t = t
	os.handler = handler
	os.waitExit = make(chan bool)
	return os, nil
}
