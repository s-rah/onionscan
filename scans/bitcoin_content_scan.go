package scans

import (
	"github.com/s-rah/onionscan/report"
	"log"
	"regexp"
)

type BitcoinContentScan struct {
}

func (cs *BitcoinContentScan) ScanContent(content string, report *report.OnionScanReport) {
	log.Printf("Scanning for Bitcoin Address\n")
	bitcoinAddressRegexp := regexp.MustCompile("[1|3][A-Za-z0-9]{25,34}")
	foundBitcoinAddress := bitcoinAddressRegexp.FindAllString(content, -1)
	for _, ba := range foundBitcoinAddress {
		log.Printf("Found Bitcoin Address: %s", ba)
		report.BitcoinAddresses = append(report.BitcoinAddresses, ba)
	}
}
