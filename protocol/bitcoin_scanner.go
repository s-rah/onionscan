package protocol

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

type BitcoinProtocolScanner struct {
}

func (rps *BitcoinProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionscanConfig, report *report.OnionScanReport) {
	// Bitcoin
	osc.LogInfo(fmt.Sprintf("Checking %s Bitcoin(8333)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 8333, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 8333\n")
		report.BitcoinDetected = false
	} else {
		osc.LogInfo("Detected possible Bitcoin instance\n")
		// TODO: Actual Analysis
		report.BitcoinDetected = true
	}
	if conn != nil {
		conn.Close()
	}
}
