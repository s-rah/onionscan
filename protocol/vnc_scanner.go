package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"log"
)

type VNCProtocolScanner struct {
}

func (vncps *VNCProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// MongoDB
	log.Printf("Checking %s VNC(5900)\n", hiddenService)
	_, err := utils.GetNetworkConnection(hiddenService, 5900, onionscanConfig.TorProxyAddress, onionscanConfig.Timeout)
	if err != nil {
		log.Printf("Failed to connect to service on port 5900\n")
		report.VNCDetected = false
	} else {
		log.Printf("Detected possible VNC instance\n")
		// TODO: Actual Analysis
		report.VNCDetected = true
	}

}
