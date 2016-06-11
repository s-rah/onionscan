package utils

import (
	"h12.me/socks"
	"net"
	"strconv"
	"time"
)

func GetNetworkConnection(onionService string, port int, proxy string, timeout time.Duration) (net.Conn, error) {
	portNumber := strconv.Itoa(port)
	conn, err := socks.DialSocksProxy(socks.SOCKS5, proxy)("", onionService+":"+portNumber)
	if err == nil {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	return conn, err
}
