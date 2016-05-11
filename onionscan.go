package main

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/protocol"
	"github.com/s-rah/onionscan/report"
	"strings"
)

type OnionScan struct {
	Config *config.OnionscanConfig
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
	hps.ScanProtocol(hiddenService, os.Config, report)

	// SSH
	sps := new(protocol.SSHProtocolScanner)
	sps.ScanProtocol(hiddenService, os.Config, report)

	// Ricochet
	rps := new(protocol.RicochetProtocolScanner)
	rps.ScanProtocol(hiddenService, os.Config, report)

	// Bitcoin
	bps := new(protocol.BitcoinProtocolScanner)
	bps.ScanProtocol(hiddenService, os.Config, report)

	//IRC
	ips := new(protocol.IRCProtocolScanner)
	ips.ScanProtocol(hiddenService, os.Config, report)

	//FTP
	fps := new(protocol.FTPProtocolScanner)
	fps.ScanProtocol(hiddenService, os.Config, report)

	//SMTP
	smps := new(protocol.SMTPProtocolScanner)
	smps.ScanProtocol(hiddenService, os.Config, report)

	return report, nil
}
