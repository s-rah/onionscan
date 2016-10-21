package onionscan

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/protocol"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"strings"
	"time"
)

type OnionScan struct {
	Config *config.OnionScanConfig
}

func (os *OnionScan) GetAllActions() []string {
	return []string{
		"web",
		"tls",
		"ssh",
		"irc",
		"rdp",
		"ricochet",
		"ftp",
		"smtp",
		"mongodb",
		"vnc",
		"xmpp",
		"bitcoin",
		"bitcoin_test",
		"litecoin",
		"dogecoin",
	}
}

func (os *OnionScan) PerformNextAction(report *report.OnionScanReport, nextAction string) error {
	switch nextAction {
	case "web":
		wps := new(protocol.HTTPProtocolScanner)
		wps.ScanProtocol(report.HiddenService, os.Config, report)
	case "tls":
		tps := new(protocol.TLSProtocolScanner)
		tps.ScanProtocol(report.HiddenService, os.Config, report)
	case "ssh":
		sps := new(protocol.SSHProtocolScanner)
		sps.ScanProtocol(report.HiddenService, os.Config, report)
	case "irc":
		ips := new(protocol.IRCProtocolScanner)
		ips.ScanProtocol(report.HiddenService, os.Config, report)
	case "rdp":
		ips := new(protocol.RDPProtocolScanner)
		ips.ScanProtocol(report.HiddenService, os.Config, report)
	case "ricochet":
		rps := new(protocol.RicochetProtocolScanner)
		rps.ScanProtocol(report.HiddenService, os.Config, report)
	case "ftp":
		fps := new(protocol.FTPProtocolScanner)
		fps.ScanProtocol(report.HiddenService, os.Config, report)
	case "smtp":
		smps := new(protocol.SMTPProtocolScanner)
		smps.ScanProtocol(report.HiddenService, os.Config, report)
	case "mongodb":
		mdbps := new(protocol.MongoDBProtocolScanner)
		mdbps.ScanProtocol(report.HiddenService, os.Config, report)
	case "vnc":
		vncps := new(protocol.VNCProtocolScanner)
		vncps.ScanProtocol(report.HiddenService, os.Config, report)
	case "xmpp":
		xmppps := new(protocol.XMPPProtocolScanner)
		xmppps.ScanProtocol(report.HiddenService, os.Config, report)
	case "bitcoin", "bitcoin_test", "litecoin", "litecoin_test", "dogecoin", "dogecoin_test":
		bps := protocol.NewBitcoinProtocolScanner(nextAction)
		bps.ScanProtocol(report.HiddenService, os.Config, report)
	case "none":
		return nil
	default:
		return fmt.Errorf("Unknown scanner %s", nextAction)
	}
	return nil
}

func (os *OnionScan) PerformNextAction(report *report.OnionScanReport) {
	switch report.NextAction {
	case "web":
		wps := new(protocol.HTTPProtocolScanner)
		wps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "tls"
	case "tls":
		tps := new(protocol.TLSProtocolScanner)
		tps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "ssh"
	case "ssh":
		sps := new(protocol.SSHProtocolScanner)
		sps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "irc"
	case "irc":
		ips := new(protocol.IRCProtocolScanner)
		ips.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "ricochet"
	case "ricochet":
		rps := new(protocol.RicochetProtocolScanner)
		rps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "ftp"
	case "ftp":
		fps := new(protocol.FTPProtocolScanner)
		fps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "smtp"
	case "smtp":
		smps := new(protocol.SMTPProtocolScanner)
		smps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "mongodb"
	case "mongodb":
		mdbps := new(protocol.MongoDBProtocolScanner)
		mdbps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "vnc"
	case "vnc":
		vncps := new(protocol.VNCProtocolScanner)
		vncps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "xmpp"
	case "xmpp":
		xmppps := new(protocol.XMPPProtocolScanner)
		xmppps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "bitcoin"
	case "bitcoin":
		bps := new(protocol.BitcoinProtocolScanner)
		bps.ScanProtocol(report.HiddenService, os.Config, report)
		report.NextAction = "none"
	case "none":
		return
	default:
		report.NextAction = "web"
	}
}

func (os *OnionScan) Scan(hiddenService string, out chan *report.OnionScanReport) {

	// Remove Extra Prefix
	hiddenService = utils.WithoutProtocol(hiddenService)

	if strings.HasSuffix(hiddenService, "/") {
		hiddenService = hiddenService[0 : len(hiddenService)-1]
	}

	report := report.NewOnionScanReport(hiddenService)

<<<<<<< HEAD
	for _, nextAction := range os.Config.Scans {
		err := os.PerformNextAction(report, nextAction)
		if err != nil {
			os.Config.LogInfo(fmt.Sprintf("Error: %s", err))
		} else {
			report.PerformedScans = append(report.PerformedScans, nextAction)
		}
		if time.Now().Sub(report.DateScanned).Seconds() > os.Config.Timeout.Seconds() {
			report.TimedOut = true
		}
	}
	if len(report.PerformedScans) != 0 {
		report.NextAction = report.PerformedScans[len(report.PerformedScans)-1]
	} else {
		report.NextAction = "none"
	}
=======
	for report.NextAction != "none" {
		os.PerformNextAction(report)
		if time.Now().Sub(report.DateScanned).Seconds() > os.Config.Timeout.Seconds() {
			report.TimedOut = true
			report.NextAction = "none"
		}
	}
>>>>>>> upstream/master

	out <- report
}
