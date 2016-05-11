package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type FTPProtocolScanner struct {
}

func (sps *FTPProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// FTP
	log.Printf("Checking %s FTP(22)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)("", hiddenService+":21")
	if err != nil {
		log.Printf("Failed to connect to service on port 21\n")
	} else {
		// TODO FTP Checking
		report.FTPDetected = true
	}

}
