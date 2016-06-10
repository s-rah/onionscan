package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"log"
)

type XMPPProtocolScanner struct {
}

func (rps *XMPPProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// XMPP
	log.Printf("Checking %s XMPP(5222)\n", hiddenService)
	_, err := utils.GetNetworkConnection(hiddenService, 5222, onionscanConfig.TorProxyAddress, onionscanConfig.Timeout)
	if err != nil {
		log.Printf("Failed to connect to service on port 5222\n")
		report.XMPPDetected = false
	} else {
		log.Printf("Detected possible XMPP instance\n")
		// TODO: Actual Analysis
		report.XMPPDetected = true
	}

	// XMPP
	log.Printf("Checking %s XMPP(5223)\n", hiddenService)
	_, err = utils.GetNetworkConnection(hiddenService, 5223, onionscanConfig.TorProxyAddress, onionscanConfig.Timeout)
	if err != nil {
		log.Printf("Failed to connect to service on port 5223\n")
	} else {
		log.Printf("Detected possible XMPP (secure) instance\n")
		// TODO: Actual Analysis
		report.XMPPDetected = true
	}
}
