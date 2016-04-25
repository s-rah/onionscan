package protocol

import (
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type IRCProtocolScanner struct {

}

func (rps *IRCProtocolScanner) ScanProtocol(hiddenService string, proxyAddress string, report *report.OnionScanReport) {
	// IRC
	log.Printf("Checking %s IRC(6667)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, proxyAddress)("", hiddenService+":6667")
	if err != nil {
		log.Printf("Failed to connect to service on port 6667\n")
	} else {
		log.Printf("Detected possible IRC instance\n")
		// TODO: Actual Analysis
		report.IRCDetected = true
	}

}
