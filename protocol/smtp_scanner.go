package protocol

import (
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type SMTPProtocolScanner struct {

}

func (sps *SMTPProtocolScanner) ScanProtocol(hiddenService string, proxyAddress string, report *report.OnionScanReport) {
	// SMTP
	log.Printf("Checking %s SMTP(25)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, proxyAddress)("", hiddenService+":25")
	if err != nil {
		log.Printf("Failed to connect to service on port 25\n")
	} else {
		// TODO SMTP Checking
		report.SMTPDetected = true
	}

}
