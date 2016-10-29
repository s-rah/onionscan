package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"strconv"
	"strings"
)

// CommonCorrelations extracts relationships from other non-web protocols
// FIXME: At somepoint we probably want to separate these out into their
// own files as non-http functionality becomes better.
func CommonCorrelations(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {

	// SSH
	if osreport.SSHKey != "" {
		osc.Database.InsertRelationship(osreport.HiddenService, "ssh", "key-fingerprint", osreport.SSHKey)
	}

	if osreport.SSHBanner != "" {
		osc.Database.InsertRelationship(osreport.HiddenService, "ssh", "software-banner", osreport.SSHBanner)
	}

	// FTP
	if osreport.FTPBanner != "" {
		osc.Database.InsertRelationship(osreport.HiddenService, "ftp", "software-banner", osreport.FTPBanner)
	}

	// SMTP
	if osreport.SMTPBanner != "" {
		osc.Database.InsertRelationship(osreport.HiddenService, "smtp", "software-banner", osreport.SMTPBanner)
	}

	// Adding all Crawl Ids to Common Correlations (this is a bit of a hack to make the webui nicer)
	for uri, crawlID := range osreport.Crawls {

		if strings.HasSuffix(uri, "/") {
			cr, err := osc.Database.GetCrawlRecord(crawlID)
			if err == nil {
				page := cr.Page
				for key, val := range page.Headers {

					osc.Database.InsertRelationship(osreport.HiddenService, "crawl", "http-header", key+":"+strings.Join(val, ";"))
				}
				osc.Database.InsertRelationship(osreport.HiddenService, "crawl", "page-info", page.Title)
			} else {
				osc.LogError(err)
			}
		}

		osc.Database.InsertRelationship(osreport.HiddenService, "crawl", "database-id", strconv.Itoa(crawlID))
	}

}
