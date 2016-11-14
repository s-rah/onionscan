package onionscan

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/protocol"
	"github.com/s-rah/onionscan/report"
	"sort"
	"time"
)

// OnionScan runs the main procol level scans
type OnionScan struct {
	Config *config.OnionScanConfig
}

// Description record for a single scan type
type scanDescription struct {
	scanner      protocol.Scanner
	runByDefault bool
}

// List of all scan types in onionscan
var allScans = map[string]scanDescription{
	"web":           {new(protocol.HTTPProtocolScanner), true},
	"tls":           {new(protocol.TLSProtocolScanner), true},
	"ssh":           {new(protocol.SSHProtocolScanner), true},
	"irc":           {new(protocol.IRCProtocolScanner), true},
	"ricochet":      {new(protocol.RicochetProtocolScanner), true},
	"ftp":           {new(protocol.FTPProtocolScanner), true},
	"smtp":          {new(protocol.SMTPProtocolScanner), true},
	"mongodb":       {new(protocol.MongoDBProtocolScanner), true},
	"vnc":           {new(protocol.VNCProtocolScanner), true},
	"xmpp":          {new(protocol.XMPPProtocolScanner), true},
	"bitcoin":       {protocol.NewBitcoinProtocolScanner("bitcoin"), true},
	"bitcoin_test":  {protocol.NewBitcoinProtocolScanner("bitcoin_test"), true},
	"litecoin":      {protocol.NewBitcoinProtocolScanner("litecoin"), true},
	"litecoin_test": {protocol.NewBitcoinProtocolScanner("litecoin_test"), false},
	"dogecoin":      {protocol.NewBitcoinProtocolScanner("dogecoin"), true},
	"dogecoin_test": {protocol.NewBitcoinProtocolScanner("dogecoin_test"), false},
	"none":          {nil, false},
}

// GetDefaultActions returns a list of all protocol level scans
// (or optionally only those that should be enabled by default).
func (os *OnionScan) GetAllActions(onlyDefault bool) []string {
	var keys []string
	for k := range allScans {
		if !onlyDefault || allScans[k].runByDefault {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// Do performs all configured protocol level scans in this run.
func (os *OnionScan) Do(osreport *report.OnionScanReport) error {

	for _, nextAction := range os.Config.Scans {
		scan, ok := allScans[nextAction]
		if scan.scanner == nil {
			if !ok { // If key was not found, give error, otherwise this was the dummy scan "none"
				os.Config.LogInfo(fmt.Sprintf("Unknown scanner %s", nextAction))
			}
			continue
		}
		scan.scanner.ScanProtocol(osreport.HiddenService, os.Config, osreport)
		osreport.PerformedScans = append(osreport.PerformedScans, nextAction)
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
