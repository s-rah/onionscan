package protocol

import (
	"github.com/s-rah/onionscan/report"
	"strings"
)

type ProtocolConfig struct {
	TorProxyAddress string
	DirectoryDepth  int
}

func Configure(torProxyAddress string, directoryDepth int) *ProtocolConfig {
	onionScan := new(ProtocolConfig)
	onionScan.TorProxyAddress = torProxyAddress
	onionScan.DirectoryDepth = directoryDepth
	return onionScan
}

func (os *ProtocolConfig) Scan(hiddenService string) (*report.OnionScanReport, error) {

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
	hps := new(HTTPProtocolScanner)
	hps.ScanProtocol(hiddenService, os, report)

	// SSH
	sps := new(SSHProtocolScanner)
	sps.ScanProtocol(hiddenService, os, report)

	// Ricochet
	rps := new(RicochetProtocolScanner)
	rps.ScanProtocol(hiddenService, os, report)

	// Bitcoin
	bps := new(BitcoinProtocolScanner)
	bps.ScanProtocol(hiddenService, os, report)

	//IRC
	ips := new(IRCProtocolScanner)
	ips.ScanProtocol(hiddenService, os, report)

	//FTP
	fps := new(FTPProtocolScanner)
	fps.ScanProtocol(hiddenService, os, report)

	//SMTP
	smps := new(SMTPProtocolScanner)
	smps.ScanProtocol(hiddenService, os, report)

	return report, nil
}
