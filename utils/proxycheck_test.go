package utils

import (
	"testing"
)

// Missing: TestCheckTorProxy - will need to mock a proxy server to test this

func TestProxyStatusMessage(t *testing.T) {
	okmsg := ProxyStatusMessage(ProxyStatusOK)
	for i := ProxyStatusOK + 1; i < proxyStatusMax; i++ {
		if ProxyStatusMessage(i) == okmsg {
			t.Errorf("Status message for %d returned same as for OK", i)
		}
	}
}
