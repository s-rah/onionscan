package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type MongoDBProtocolScanner struct {
}

func (rps *MongoDBProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// MongoDB
	log.Printf("Checking %s MongoDB(27017)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)("", hiddenService+":27017")
	if err != nil {
		log.Printf("Failed to connect to service on port 27017\n")
		report.MongoDBDetected = false
	} else {
		log.Printf("Detected possible MongoDB instance\n")
		// TODO: Actual Analysis
		report.MongoDBDetected = true
	}

}
