package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"net/url"
	"strings"
)

func CheckExposedDirectories(osreport *report.OnionScanReport, report *report.AnonymityReport, osc *config.OnionScanConfig) {
	for key, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if crawlRecord.Page.Status == 200 && strings.Contains(crawlRecord.Page.Title, "Index of") {
			uri, _ := url.Parse(key)
			report.OpenDirectories = append(report.OpenDirectories, uri.Path)
		}
	}
}
