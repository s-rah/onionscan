package protocol

import (
	"net"
	"testing"
)

type TLSIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *TLSIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *TLSIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestTLSScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &TLSIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(TLSProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.TLSDetected {
		t.Errorf("Should have detected TLS")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.TLSDetected {
		t.Errorf("Should not have detected TLS")
	}
}
