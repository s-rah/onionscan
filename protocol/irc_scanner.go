package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"log"
)

type IRCProtocolScanner struct {
}

func (rps *IRCProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// IRC
	log.Printf("Checking %s IRC(6667)\n", hiddenService)
	_, err := utils.GetNetworkConnection(hiddenService, 6667, onionscanConfig.TorProxyAddress, onionscanConfig.Timeout)
	if err != nil {
		log.Printf("Failed to connect to service on port 6667\n")
		report.IRCDetected = false
	} else {
		log.Printf("Detected possible IRC instance\n")
		// TODO: Actual Analysis
		report.IRCDetected = true
	}

	// IRC
	log.Printf("Checking %s IRC(6697)\n", hiddenService)
	_, err = utils.GetNetworkConnection(hiddenService, 6697, onionscanConfig.TorProxyAddress, onionscanConfig.Timeout)
	if err != nil {
		log.Printf("Failed to connect to service on port 6697\n")
	} else {
		log.Printf("Detected possible IRC (secure) instance\n")
		// TODO: Actual Analysis
		report.IRCDetected = true
	}
}
