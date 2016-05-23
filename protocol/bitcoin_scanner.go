package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type BitcoinProtocolScanner struct {
}

func (rps *BitcoinProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// Bitcoin
	log.Printf("Checking %s Bitcoin(8333)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)("", hiddenService+":8333")
	if err != nil {
		log.Printf("Failed to connect to service on port 8333\n")
		report.BitcoinDetected = false
	} else {
		log.Printf("Detected possible Bitcoin instance\n")
		// TODO: Actual Analysis
		report.BitcoinDetected = true
	}

}
