package protocol

import (
	"net"
	"testing"
)

type HTTPIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *HTTPIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *HTTPIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestHTTPScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &HTTPIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(HTTPProtocolScanner)
	r := MockCheckHiddenServiceWithDatabase(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if (!r.WebDetected) {
		t.Errorf("Should have detected HTTP")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.WebDetected {
		t.Errorf("Should not have detected HTTP")
	}
}
