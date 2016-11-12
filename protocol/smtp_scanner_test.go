package protocol

import (
	"net"
	"testing"
)

type SMTPIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *SMTPIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *SMTPIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestSMTPScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &SMTPIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(SMTPProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.SMTPDetected {
		t.Errorf("Should have detected SMTP")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.SMTPDetected {
		t.Errorf("Should not have detected SMTP")
	}
}
