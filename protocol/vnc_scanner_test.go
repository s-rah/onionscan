package protocol

import (
	"net"
	"testing"
)

type VNCIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *VNCIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *VNCIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestVNCScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &VNCIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(VNCProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.VNCDetected {
		t.Errorf("Should have detected VNC")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.VNCDetected {
		t.Errorf("Should not have detected VNC")
	}
}
