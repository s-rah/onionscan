package deanonymization

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/model"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// GetOnionLinks extracts links and urls from the current crawl
func GetOnionLinks(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {

	linkmap := make(map[string]bool)
	urlmap := make(map[string]bool)

	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {

			var entities []model.Element
			entities = append(entities, crawlRecord.Page.Anchors...)
			entities = append(entities, crawlRecord.Page.Links...)
			entities = append(entities, crawlRecord.Page.Images...)
			entities = append(entities, crawlRecord.Page.Scripts...)

			for _, link := range entities {
				ref, err := url.Parse(link.Target)
				if err == nil {
					host := ref.Host
					if strings.Contains(ref.Host, ":") {
						host, _, _ = net.SplitHostPort(ref.Host)
					}

					if utils.IsOnion(host) {
						if linkmap[host] == false && host != osreport.HiddenService {
							osc.LogInfo(fmt.Sprintf("Found Onion %s", host))
							linkmap[host] = true
						}
					} else {
						if strings.HasPrefix(ref.String(), "data:") {
							// Ignore Data URI
						} else {
							urlmap[ref.String()] = true
						}
					}
				} // This will ignore [embedded document] URLs
			}

			// FIXME: This can be smarter
			onionregex := regexp.MustCompile(`[a-z2-7]{16}\.onion`)
			foundOnions := onionregex.FindAllString(crawlRecord.Page.Snapshot, -1)

			for _, host := range foundOnions {
				if linkmap[host] == false && host != osreport.HiddenService {
					osc.LogInfo(fmt.Sprintf("Found Onion %s", host))
					linkmap[host] = true
				}
			}
		}
	}

	for uri := range urlmap {
		osc.Database.InsertRelationship(osreport.HiddenService, "clearnetlink", "uri", uri)
	}

	for onion := range linkmap {
		anonreport.LinkedOnions = append(anonreport.LinkedOnions, onion)
		osc.Database.InsertRelationship(osreport.HiddenService, "links", "uri", onion)
	}
}
