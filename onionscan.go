package main

import (
	"github.com/s-rah/onionscan/protocol"
	"github.com/s-rah/onionscan/report"
	"strings"
)

type OnionScan struct {
	TorProxyAddress string
}

func Configure(torProxyAddress string) *OnionScan {
	onionScan := new(OnionScan)
	onionScan.TorProxyAddress = torProxyAddress
	return onionScan
}

func (os *OnionScan) Scan(hiddenService string) (*report.OnionScanReport, error) {

	// Remove Extra Prefix
	// TODO: Add support for HTTPS?
	if strings.HasPrefix(hiddenService, "http://") {
		hiddenService = hiddenService[7:]
	}

	if strings.HasSuffix(hiddenService, "/") {
		hiddenService = hiddenService[0 : len(hiddenService)-1]
	}

	report := report.NewOnionScanReport(hiddenService)

	// HTTP
	hps := new(protocol.HTTPProtocolScanner)
	hps.ScanProtocol(hiddenService, os.TorProxyAddress, report)

	// SSH
	sps := new(protocol.SSHProtocolScanner)
	sps.ScanProtocol(hiddenService, os.TorProxyAddress, report)

	// Ricochet
	rps := new(protocol.RicochetProtocolScanner)
	rps.ScanProtocol(hiddenService, os.TorProxyAddress, report)

	return report, nil
}
