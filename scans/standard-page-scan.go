package scans

import (
	"crypto/sha1"
	"encoding/hex"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"log"
	"net/url"
	"regexp"
	"strings"
)

func StandardPageScan(scan Scanner, page string, status int, contents string, report *report.OnionScanReport) {
	log.Printf("Scanning %s%s\n", report.HiddenService, page)
	if status == 200 {
		log.Printf("\tPage %s%s is Accessible\n", report.HiddenService, page)

		hash := sha1.Sum([]byte(contents))
		report.Hashes = append(report.Hashes, hex.EncodeToString(hash[:]))
		report.Snapshot = contents

		// Try resolve page title if present
		isTitlePresent := strings.Contains(contents, "<title>")
		if isTitlePresent {
			var startIndex = strings.Index(contents, "<title>")
			var endIndex = strings.Index(contents, "</title>")
			var pageTitle = contents[startIndex+len("<title>") : endIndex]
			log.Printf("\tPage Title: %s\n", pageTitle)
			report.PageTitle = pageTitle
		}

		new(PGPContentScan).ScanContent(contents, report)
		domains := utils.ExtractDomains(contents)

		for _, domain := range domains {
			if !strings.HasPrefix(domain, "http://"+report.HiddenService) {
				log.Printf("Found Related URL %s\n", domain)
				// TODO: Lots of information here which needs to be processed.
				// * Links to standard sites - google / bitpay etc.
				// * Links to other onion sites
				// * Links to obscure clearnet sites.
				baseUrl, _ := url.Parse(domain)
				report.AddLinkedSite(baseUrl.Host)
			} else {
				// * Process FQDN internal links (unlikly)
				log.Printf("Found Internal URL %s\n", domain)
			}
		}

		log.Printf("\tScanning for Images\n")
		r := regexp.MustCompile("src=\"(" + "http://" + report.HiddenService + "/)?((.*?\\.jpg)|(.*?\\.png)|(.*?\\.jpeg)|(.*?\\.gif))\"")
		foundImages := r.FindAllStringSubmatch(string(contents), -1)
		for _, image := range foundImages {
			log.Printf("\t Found image %s\n", image[2])
			scan.ScanPage(report.HiddenService, "/"+image[2], report, CheckExif)
		}

		log.Printf("\tScanning for Referenced Directories\n")
		r = regexp.MustCompile("(src|href)=\"([^\"]*)\"")
		foundPaths := r.FindAllStringSubmatch(string(contents), -1)
		for _, regexpResults := range foundPaths {
			path := regexpResults[2]
			if strings.HasPrefix(path, "http") {
				continue
			}

			term := strings.LastIndex(path, "/")
			if term > 0 {
				log.Printf("\t Found Referenced Directory %s\n", path[:term])
				report.AddPageReferencedDirectory(path[:term])
			}
		}
	} else if status == 403 {
		log.Printf("\tPage %s%s is Forbidden\n", report.HiddenService, page)
	} else if status == 404 {
		log.Printf("\tPage %s%s is Does Not Exist\n", report.HiddenService, page)
	}
}
