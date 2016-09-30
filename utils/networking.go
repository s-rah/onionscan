package utils

import (
	"golang.org/x/net/proxy"
	"net"
	"strconv"
	"time"
)

func GetNetworkConnection(onionService string, port int, proxyAddress string, timeout time.Duration) (net.Conn, error) {
	portNumber := strconv.Itoa(port)
	torDialer, err := proxy.SOCKS5("tcp", proxyAddress, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	conn, err := torDialer.Dial("tcp", onionService+":"+portNumber)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	return conn, err
}
