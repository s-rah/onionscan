package main

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/protocol"
	"github.com/s-rah/onionscan/report"
	"strings"
)

func onionscan(onionscanConfig *config.OnionscanConfig, hiddenService string) (*report.OnionScanReport, error) {

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
	hps.ScanProtocol(hiddenService, onionscanConfig, report)

	// SSH
	sps := new(protocol.SSHProtocolScanner)
	sps.ScanProtocol(hiddenService, onionscanConfig, report)

	// Ricochet
	rps := new(protocol.RicochetProtocolScanner)
	rps.ScanProtocol(hiddenService, onionscanConfig, report)

	// Bitcoin
	bps := new(protocol.BitcoinProtocolScanner)
	bps.ScanProtocol(hiddenService, onionscanConfig, report)

	//IRC
	ips := new(protocol.IRCProtocolScanner)
	ips.ScanProtocol(hiddenService, onionscanConfig, report)

	//FTP
	fps := new(protocol.FTPProtocolScanner)
	fps.ScanProtocol(hiddenService, onionscanConfig, report)

	//SMTP
	smps := new(protocol.SMTPProtocolScanner)
	smps.ScanProtocol(hiddenService, onionscanConfig, report)

	return report, nil
}
