package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"regexp"
	"strings"
)

// ExtractGoogleAnalyticsID extracts any Google analytics IDs e.g. UA-32423-7564
func ExtractGoogleAnalyticsID(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {
	garegex := regexp.MustCompile(`UA-\d{4,10}-\d{1,4}\b`)
	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {
			foundGA := garegex.FindAllString(crawlRecord.Page.Snapshot, -1)

			for _, result := range foundGA {
				anonreport.AnalyticsIDs = append(anonreport.AnalyticsIDs, result)
				osc.Database.InsertRelationship(osreport.HiddenService, "snapshot", "analytics-id", result)
			}
		}
	}
}
