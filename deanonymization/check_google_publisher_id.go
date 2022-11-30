package deanonymization

import (
	"github.com/csimsv/onionscan/config"
	"github.com/csimsv/onionscan/report"
	"regexp"
	"strings"
)

// ExtractGooglePublisherID extract Google publisher ids, used for adsense marketing
// e.g. pub-230210202
func ExtractGooglePublisherID(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {
	gpregex := regexp.MustCompile(`pub-[0-9]+`)
	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {
			foundGPID := gpregex.FindAllString(crawlRecord.Page.Snapshot, -1)

			for _, result := range foundGPID {
				// Add it to analytics ids as it is essentially a tracking metric
				anonreport.AnalyticsIDs = append(anonreport.AnalyticsIDs, result)
				osc.Database.InsertRelationship(osreport.HiddenService, "snapshot", "analytics-id", result)
			}
		}
	}
}
