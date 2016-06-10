package main

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/protocol"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"strings"
)

type OnionScan struct {
	Config *config.OnionscanConfig
}

func (os *OnionScan) Scan(hiddenService string, out chan *report.OnionScanReport) {

	// Remove Extra Prefix
	hiddenService = utils.WithoutProtocol(hiddenService)

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

	//MongoDb
	mdbps := new(protocol.MongoDBProtocolScanner)
	mdbps.ScanProtocol(hiddenService, os.Config, report)

	//VNC
	vncps := new(protocol.VNCProtocolScanner)
	vncps.ScanProtocol(hiddenService, os.Config, report)

	//XMPP
	xmppps := new(protocol.XMPPProtocolScanner)
	xmpps.ScanProtocol(hiddenService, os.Config, report)

	out <- report
}
