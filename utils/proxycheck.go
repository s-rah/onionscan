package utils

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ProxyStatus int

const (
	ProxyStatusOK ProxyStatus = iota
	ProxyStatusWrongType
	ProxyStatusCannotConnect
	ProxyStatusTimeout
)

// Detect whether a proxy is connectable and is a Tor proxy
func CheckTorProxy(proxyAddress string) ProxyStatus {
	// A trick to do this without making an outward connection is,
	// paradoxically, to try to open it as http.
	// This is documented in section 4 here: https://github.com/torproject/torspec/blob/master/socks-extensions.txt
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + proxyAddress + "/")
	if err != nil {
		switch t := err.(type) {
		case *url.Error:
			switch t.Err.(type) {
			case *net.OpError: // Network-level error. Will in turn contain a os.SyscallError
				return ProxyStatusCannotConnect
			default:
				// http.error unfortunately not exported, need to match on string
				// net/http: request canceled
				if strings.Index(t.Err.Error(), "request canceled") != -1 {
					return ProxyStatusTimeout
				}
			}
		}
		// Protocol-level errors mean that http failed, so it's not Tor
		return ProxyStatusWrongType
	}
	defer response.Body.Close()
	if response.Status != "501 Tor is not an HTTP Proxy" {
		return ProxyStatusWrongType
	}
	return ProxyStatusOK
}

func ProxyStatusMessage(status ProxyStatus) string {
	switch status {
	case ProxyStatusWrongType:
		return "Proxy specified is not a Tor proxy"
	case ProxyStatusCannotConnect:
		return "Cannot connect to Tor proxy"
	case ProxyStatusTimeout:
		return "Proxy timeout"
	default:
		return "Unknown proxy error"
	}
}
