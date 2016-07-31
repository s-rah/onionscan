package protocol

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

type IRCProtocolScanner struct {
}

func (rps *IRCProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionscanConfig, report *report.OnionScanReport) {
	// IRC
	osc.LogInfo(fmt.Sprintf("Checking %s IRC(6667)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 6667, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 6667\n")
		report.IRCDetected = false
	} else {
		osc.LogInfo("Detected possible IRC instance\n")
		// TODO: Actual Analysis
		report.IRCDetected = true
	}
	if conn != nil {
		conn.Close()
	}

	// IRC
	osc.LogInfo(fmt.Sprintf("Checking %s IRC(6697)\n", hiddenService))
	conn, err = utils.GetNetworkConnection(hiddenService, 6697, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 6697\n")
	} else {
		osc.LogInfo("Detected possible IRC (secure) instance\n")
		// TODO: Actual Analysis
		report.IRCDetected = true
	}
	if conn != nil {
		conn.Close()
	}
}
