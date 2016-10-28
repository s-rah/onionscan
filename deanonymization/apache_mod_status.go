package deanonymization

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"net/url"
	"regexp"
	"strings"
)

// ApacheModStatus extracts any information related to exposed mod_status endpoints.
// FIXME: We can make this much smarted than it currently is.
func ApacheModStatus(osreport *report.OnionScanReport, report *report.AnonymityReport, osc *config.OnionScanConfig) {
	modStatus, _ := url.Parse("http://" + osreport.HiddenService + "/server-status")
	id := osreport.Crawls[modStatus.String()]
	crawlRecord, _ := osc.Database.GetCrawlRecord(id)
	if crawlRecord.Page.Status == 200 {
		contents := crawlRecord.Page.Snapshot

		r := regexp.MustCompile(`Server Version: (.*)</dt>`)
		serverVersion := r.FindStringSubmatch(string(contents))

		// Check if this looks like a mod_status page. Sometimes sites simply load their index.
		if len(serverVersion) > 1 {
			osc.LogInfo("Detected Apache mod_status Exposed...\033[091mAlert!\033[0m\n")
			report.FoundApacheModStatus = true

			osc.LogInfo(fmt.Sprintf("\t Using mod_status Server Version: %s\n", serverVersion[1]))
			report.ServerVersion = serverVersion[1]
			osc.Database.InsertRelationship(osreport.HiddenService, "mod_status", "server-version", serverVersion[1])

			r = regexp.MustCompile(`<td>(.*)</td><td nowrap>(.*)</td><td nowrap>(.*)</td></tr>`)
			foundServices := r.FindAllStringSubmatch(string(contents), -1)

			for _, foundServices := range foundServices {
				client := foundServices[1]
				vhost := foundServices[2]

				if strings.TrimSpace(client) != "" {
					osc.Database.InsertRelationship(osreport.HiddenService, "mod_status", "ip", client)
				}

				if len(vhost) >= 22 && strings.Contains(vhost, ".onion") && vhost != osreport.HiddenService {
					osc.Database.InsertRelationship(osreport.HiddenService, "mod_status", "onion", vhost)

					withoutPort := strings.SplitN(vhost, ":", 2)
					osc.LogInfo(fmt.Sprintf("%v", withoutPort))
					if withoutPort[0] != vhost && withoutPort[0] != osreport.HiddenService {
						osc.Database.InsertRelationship(osreport.HiddenService, "mod_status", "onion", withoutPort[0])
					}
				} else if strings.TrimSpace(vhost) != "" && vhost != osreport.HiddenService {
					osc.Database.InsertRelationship(osreport.HiddenService, "mod_status", "clearnet-link", vhost)
					withoutPort := strings.SplitN(vhost, ":", 2)
					osc.LogInfo(fmt.Sprintf("%v", withoutPort))
					if withoutPort[0] != vhost && vhost != osreport.HiddenService {
						osc.Database.InsertRelationship(osreport.HiddenService, "mod_status", "clearnet-link", withoutPort[0])
					}

				}

			}

		}
	}
}
