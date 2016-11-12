package protocol

import (
	"net"
	"testing"
)

type RicochetIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *RicochetIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *RicochetIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestRicochetScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &RicochetIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(RicochetProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.RicochetDetected {
		t.Errorf("Should have detected Ricochet")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.RicochetDetected {
		t.Errorf("Should not have detected Ricochet")
	}
}
