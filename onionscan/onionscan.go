package onionscan

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/protocol"
	"github.com/s-rah/onionscan/report"
	"time"
)

// OnionScan runs the main procol level scans
type OnionScan struct {
	Config *config.OnionScanConfig
}

// GetAllActions returns a list of all possible protocol level  scans.
func (os *OnionScan) GetAllActions() []string {
	return []string{
		"web",
		"tls",
		"ssh",
		"irc",
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

// PerformNextAction  determined which scan to run next, and runs it.
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

// Do performs all configured protocol level scans in this run.
func (os *OnionScan) Do(osreport *report.OnionScanReport) error {

	for _, nextAction := range os.Config.Scans {
		err := os.PerformNextAction(osreport, nextAction)
		if err != nil {
			os.Config.LogInfo(fmt.Sprintf("Error: %s", err))
		} else {
			osreport.PerformedScans = append(osreport.PerformedScans, nextAction)
		}
		if time.Now().Sub(osreport.DateScanned).Seconds() > os.Config.Timeout.Seconds() {
			osreport.TimedOut = true
			break
		}
	}
	if len(osreport.PerformedScans) != 0 {
		osreport.NextAction = osreport.PerformedScans[len(osreport.PerformedScans)-1]
	} else {
		osreport.NextAction = "none"
	}
	return nil
}
