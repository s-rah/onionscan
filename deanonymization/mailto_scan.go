package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"strings"
)

func MailtoScan(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {

	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {
			for _, anchor := range crawlRecord.Page.Anchors {
				if strings.HasPrefix(anchor.Target, "mailto:") {
					anonreport.EmailAddresses = append(anonreport.EmailAddresses, anchor.Target[7:])
				}
			}
		}
	}
}
