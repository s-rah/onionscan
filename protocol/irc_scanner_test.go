package protocol

import (
	"net"
	"testing"
)

type IRCIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *IRCIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *IRCIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestIRCScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &IRCIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(IRCProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.IRCDetected {
		t.Errorf("Should have detected IRC")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.IRCDetected {
		t.Errorf("Should not have detected IRC")
	}
}
