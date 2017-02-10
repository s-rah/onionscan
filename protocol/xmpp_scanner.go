package protocol

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

type XMPPProtocolScanner struct {
}

func (rps *XMPPProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionScanConfig, report *report.OnionScanReport) {
	// XMPP
	ports := []int{5222,5223}
	for _, port := range ports {
			osc.LogInfo(fmt.Sprintf("Checking %s XMPP(%d)\n", hiddenService, port))
			conn, err := utils.GetNetworkConnection(hiddenService, port, osc.TorProxyAddress, osc.Timeout)
		if err != nil {
			osc.LogInfo(fmt.Sprintf("Failed to connect to service on port %d\n", port))
			report.XMPPDetected = false
		} else {
			osc.LogInfo("Detected possible XMPP instance\n")
		// TODO: Actual Analysis
			report.XMPPDetected = true
		}
		if conn != nil {
		conn.Close()
		}
	}
}
