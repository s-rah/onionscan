package protocol

import (
	"net"
	"testing"
)

type XMPPIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *XMPPIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *XMPPIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestXMPPScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &XMPPIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(XMPPProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.XMPPDetected {
		t.Errorf("Should have detected XMPP")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.XMPPDetected {
		t.Errorf("Should not have detected XMPP")
	}
}
