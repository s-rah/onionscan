package protocol

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

type RDPProtocolScanner struct {
}

func (rdpps *RDPProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionScanConfig, report *report.OnionScanReport) {
	// RDP
	osc.LogInfo(fmt.Sprintf("Checking %s RDP(3389)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 3389, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 3389\n")
		report.RDPDetected = false
	} else {
		osc.LogInfo("Detected possible RDP instance\n")
		// TODO: Actual Analysis
		report.RDPDetected = true
	}
	if conn != nil {
		conn.Close()
	}
}
