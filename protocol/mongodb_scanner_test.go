package protocol

import (
	"net"
	"testing"
)

type MongoDBIncomingConnectionHandler struct {
	t *testing.T
}

func (handler *MongoDBIncomingConnectionHandler) ConnectionSucceeds(domainname string, port uint16) bool {
	return domainname == "haxaxaxaxaxaxaxa.onion"
}
func (handler *MongoDBIncomingConnectionHandler) HandleConnection(domainname string, port uint16, conn net.Conn) {
	// TODO: further protocol handling
}

func TestMongoDBScanProtocol(t *testing.T) {
	proxy, err := NewTestSOCKS5Server(t, &MongoDBIncomingConnectionHandler{t})
	if err != nil {
		return
	}
	proxy.Start()
	defer proxy.Stop()

	bps := new(MongoDBProtocolScanner)

	r := MockCheckHiddenService(t, proxy, bps, "haxaxaxaxaxaxaxa.onion")
	if !r.MongoDBDetected {
		t.Errorf("Should have detected MongoDB")
	}
	r = MockCheckHiddenService(t, proxy, bps, "nononononononono.onion")
	if r.MongoDBDetected {
		t.Errorf("Should not have detected MongoDB")
	}
}
