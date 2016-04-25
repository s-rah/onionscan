package protocol

import (
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type RicochetProtocolScanner struct {

}

func (rps *RicochetProtocolScanner) ScanProtocol(hiddenService string, proxyAddress string, report *report.OnionScanReport) {
	// Ricochet
	log.Printf("Checking %s ricochet(9878)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, proxyAddress)("", hiddenService+":9878")
	if err != nil {
		log.Printf("Failed to connect to service on port 9878\n")
	} else {
		log.Printf("Detected possible ricochet instance\n")
		// TODO: Actual Analysis
		report.RicochetDetected = true
	}

}
