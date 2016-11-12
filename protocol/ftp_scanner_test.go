package protocol

import (
	"net"
	"testing"
)

type FTPIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *FTPIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *FTPIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestFTPScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &FTPIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(FTPProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.FTPDetected {
		t.Errorf("Should have detected FTP")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.FTPDetected {
		t.Errorf("Should not have detected FTP")
	}
}
