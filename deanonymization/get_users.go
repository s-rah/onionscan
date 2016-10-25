package deanonymization

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"regexp"
	"strings"
)

// GetUserDefinedRelationships extracts any user configured relationships from
// the current crawl
func GetUserDefinedRelationships(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {

	config, ok := osc.CrawlConfigs[osreport.HiddenService]
	if ok {
		for uri, id := range osreport.Crawls {
			crawlRecord, _ := osc.Database.GetCrawlRecord(id)
			if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {

				for _, relationship := range config.Relationships {
					r := regexp.MustCompile(relationship.TriggerIdentifierRegex)
					result := r.FindAllStringSubmatch(uri, 1)
					if len(result) == 1 {
						osc.LogInfo(fmt.Sprintf("Triggered %s Relationship - Found Identifier: %s", relationship.Name, result[0][1]))
						osc.Database.InsertRelationship(osreport.HiddenService, relationship.Name, "user-relationship", result[0][1])

						id := result[0][1]

						for _, er := range relationship.ExtraRelationships {
							r = regexp.MustCompile(er.Regex)
							result = r.FindAllStringSubmatch(crawlRecord.Page.Snapshot, -1)
							if len(result) >= 1 {
								osc.LogInfo(fmt.Sprintf("Found Relationship %s: %s", er.Name, result[0][1]))
								osc.Database.InsertRelationship(id, osreport.HiddenService, relationship.Name+"/"+er.Name, result[0][1])
							}
						}

					}
				}
			}
		}
	}
}
