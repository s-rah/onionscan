package scans

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"regexp"
	"strings"
)

func ApacheModStatus(scan Scanner, page string, status int, contents string, report *report.OnionScanReport, osc *config.OnionscanConfig) {
	if status == 200 {
		r := regexp.MustCompile(`Server Version: (.*)</dt>`)
		serverVersion := r.FindStringSubmatch(string(contents))

		// Check if this looks like a mod_status page. Sometimes sites simply load their index.
		if len(serverVersion) > 1 {
			osc.LogInfo("Detected Apache mod_status Exposed...\033[091mAlert!\033[0m\n")
			report.FoundApacheModStatus = true

			osc.LogInfo(fmt.Sprintf("\t Using mod_status Server Version: %s\n", serverVersion[1]))
			report.ServerVersion = serverVersion[1]

			// Check for co-hosted onion services.
			osc.LogInfo("Scanning for Co-Hosted Onions\n")
			r = regexp.MustCompile(`[a-z0-9]+.onion(:[0-9]{0-5})?`)
			foundServices := r.FindAllString(string(contents), -1)
			utils.RemoveDuplicates(&foundServices)
			for _, onion := range foundServices {
				if onion != report.HiddenService {
					osc.LogInfo(fmt.Sprintf("\t \033[091mAlert!\033[0m Found Co-Hosted Onions: %s\n", onion))
					report.AddRelatedOnionService(onion)
				}
			}

			// Check for co-hosted onion services.
			osc.LogInfo("Scanning for Co-Hosted Clearnet Domains\n")
			r = regexp.MustCompile(`>(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})`)
			foundServices = r.FindAllString(string(contents), -1)
			utils.RemoveDuplicates(&foundServices)
			for _, domain := range foundServices {
				if strings.Contains(domain, ".onion") == false {
					osc.LogInfo(fmt.Sprintf("\t \033[091mAlert!\033[0m Found Co-Hosted Service: %s\n", domain[1:]))
					report.AddRelatedClearnetDomain(domain[4:])
				}
			}

			// Check for IP Addresses
			osc.LogInfo("Scanning for IP Addresses (clearweb clients, and servers)\n")
			r = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)
			foundIPs := r.FindAllString(string(contents), -1)
			utils.RemoveDuplicates(&foundIPs)
			for _, ip := range foundIPs {
				if ip != "127.0.0.1" {
					osc.LogInfo(fmt.Sprintf("\t \033[091mAlert!\033[0m Found IP Address : %s\n", ip))
					report.AddIPAddress(ip)
				}
			}

		}
	}
	if !report.FoundApacheModStatus {
		osc.LogInfo("\tApache mod_status Not Exposed...\033[92mGood!\033[0m\n")
		report.FoundApacheModStatus = false
	}
}
