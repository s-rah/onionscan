package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"regexp"
	"strings"
)

// EmailScan extracts anything which resembles an email address from the current crawl.
func EmailScan(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {

	mailRegexp := regexp.MustCompile(`(\w[-._\w]*\w@\w[-._\w]*\w\.\w{2,16})`)

	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {
			foundEmail := mailRegexp.FindAllString(crawlRecord.Page.Snapshot, -1)
			for _, email := range foundEmail {
				anonreport.EmailAddresses = append(anonreport.EmailAddresses, email)
				osc.Database.InsertRelationship(osreport.HiddenService, "snapshot", "email-address", email)
			}
		}
	}
}
