package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type VNCProtocolScanner struct {
}

func (vncps *VNCProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// MongoDB
	log.Printf("Checking %s VNC(5900)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)("", hiddenService+":5900")
	if err != nil {
		log.Printf("Failed to connect to service on port 5900\n")
		report.VNCDetected = false
	} else {
		log.Printf("Detected possible VNC instance\n")
		// TODO: Actual Analysis
		report.VNCDetected = true
	}

}
