package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"log"
)

type RicochetProtocolScanner struct {
}

func (rps *RicochetProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// Ricochet
	log.Printf("Checking %s ricochet(9878)\n", hiddenService)
	_, err := utils.GetNetworkConnection(hiddenService, 9878, onionscanConfig.TorProxyAddress, onionscanConfig.Timeout)
	if err != nil {
		log.Printf("Failed to connect to service on port 9878\n")
		report.RicochetDetected = false
	} else {
		log.Printf("Detected possible ricochet instance\n")
		// TODO: Actual Analysis
		report.RicochetDetected = true
	}

}
