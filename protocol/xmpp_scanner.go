package protocol

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

type XMPPProtocolScanner struct {
}

func (rps *XMPPProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionscanConfig, report *report.OnionScanReport) {
	// XMPP
	osc.LogInfo(fmt.Sprintf("Checking %s XMPP(5222)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 5222, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 5222\n")
		report.XMPPDetected = false
	} else {
		osc.LogInfo("Detected possible XMPP instance\n")
		// TODO: Actual Analysis
		report.XMPPDetected = true
	}
	if conn != nil {
		conn.Close()
	}
	// XMPP
	osc.LogInfo(fmt.Sprintf("Checking %s XMPP(5223)\n", hiddenService))
	conn, err = utils.GetNetworkConnection(hiddenService, 5223, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 5223\n")
	} else {
		osc.LogInfo("Detected possible XMPP (secure) instance\n")
		// TODO: Actual Analysis
		report.XMPPDetected = true
	}
	if conn != nil {
		conn.Close()
	}
}
