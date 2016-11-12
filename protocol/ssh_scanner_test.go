package protocol

import (
	"net"
	"testing"
)

type SSHIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *SSHIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *SSHIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestSSHScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &SSHIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(SSHProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.SSHDetected {
		t.Errorf("Should have detected SSH")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.SSHDetected {
		t.Errorf("Should not have detected SSH")
	}
}
