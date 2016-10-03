package deanonymization

import (
	"net/url"

	"encoding/base64"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"strings"
)

func ProcessKey(osreport *report.OnionScanReport, report *report.AnonymityReport, osc *config.OnionScanConfig, key string) {
	_, err := base64.StdEncoding.DecodeString(key)
	if err == nil { // Parses as base64 - could further check data as DER key, but this seems enough
		report.PrivateKeyDetected = true
	}
}

func PrivateKey(osreport *report.OnionScanReport, report *report.AnonymityReport, osc *config.OnionScanConfig) {
	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)

		uri, _ := url.Parse(crawlRecord.URL)
		if crawlRecord.Page.Status == 200 && strings.HasSuffix(uri.Path, "/private_key") {
			contents := crawlRecord.Page.Snapshot

			key := ""
			inKey := false
			for _, line := range strings.Split(contents, "\n") {
				line := strings.TrimSpace(line)
				if line == "-----BEGIN RSA PRIVATE KEY-----" {
					inKey = true
					key = ""
				} else if line == "-----END RSA PRIVATE KEY-----" {
					ProcessKey(osreport, report, osc, key)
					inKey = false
				} else if inKey {
					key += line
				}
			}
		}
	}
}
