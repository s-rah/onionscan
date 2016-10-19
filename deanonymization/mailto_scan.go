package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"strings"
)

// MailtoScan Extracts any email addresses linked via mailto targets.
func MailtoScan(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {

	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {
			for _, anchor := range crawlRecord.Page.Anchors {
				if strings.HasPrefix(anchor.Target, "mailto:") {
					anonreport.EmailAddresses = append(anonreport.EmailAddresses, anchor.Target[7:])
					osc.Database.InsertRelationship(osreport.HiddenService, "mailto", "email-address", anchor.Target[7:])
				}
			}
		}
	}
}
