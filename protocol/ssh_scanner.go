package protocol

import (
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type SSHProtocolScanner struct {

}

func (sps *SSHProtocolScanner) ScanProtocol(hiddenService string, proxyAddress string, report *report.OnionScanReport) {
	// SSH
	log.Printf("Checking %s ssh(22)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, proxyAddress)("", hiddenService+":22")
	if err != nil {
		log.Printf("Failed to connect to service on port 22\n")
	} else {
		// TODO SSH Checking
	}

}
