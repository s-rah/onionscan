package scans

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"golang.org/x/net/html"
	"net/url"
	"regexp"
	"strings"
)

func StandardPageScan(scan Scanner, page string, status int, contents string, report *report.OnionScanReport, osc *config.OnionscanConfig) {
	osc.LogInfo(fmt.Sprintf("Scanning %s\n", page))
	if status == 200 {
		osc.LogInfo(fmt.Sprintf("\tPage %s is Accessible\n", page))

		hash := sha1.Sum([]byte(contents))
		report.Hashes = append(report.Hashes, hex.EncodeToString(hash[:]))
		report.Snapshot = contents

		// Try resolve page title if present
		isTitlePresent := strings.Contains(contents, "<title>")
		if isTitlePresent {
			var startIndex = strings.Index(contents, "<title>")
			var endIndex = strings.Index(contents, "</title>")
			var pageTitle = contents[startIndex+len("<title>") : endIndex]
			osc.LogInfo(fmt.Sprintf("\tPage Title: %s\n", pageTitle))
			report.PageTitle = pageTitle
		}

		new(PGPContentScan).ScanContent(contents, report)
		//new(BitcoinContentScan).ScanContent(contents, report)

		osc.LogInfo("\tScanning for Images\n")
		var domains []string
		var cssLinks []string

		// parser based on http://schier.co/blog/2015/04/26/a-simple-web-scraper-in-go.html
		z := html.NewTokenizer(strings.NewReader(contents))
		for {
			tt := z.Next()
			if tt == html.ErrorToken {
				break
			}
			t := z.Token()

			// check for an href and src attributes
			// TODO: don't crawl links with nofollow

			if tt == html.StartTagToken {
				// links
				if t.Data == "a" {
					linkUrl := utils.GetAttribute(t, "href")
					if len(linkUrl) > 1 {
						domains = append(domains, linkUrl)
					}
				}
			}

			// css <link>
			if t.Data == "link" && utils.GetAttribute(t, "rel") == "stylesheet" {
				cssLinks = append(cssLinks, utils.GetAttribute(t, "href"))
			}

			// images
			if t.Data == "img" {
				imageUrl := utils.GetAttribute(t, "src")

				baseUrl, err := url.Parse(imageUrl)
				if err == nil {
					if utils.WithoutSubdomains(baseUrl.Host) == utils.WithoutSubdomains(report.HiddenService) {
						scan.ScanPage(report.HiddenService, utils.WithoutProtocol(imageUrl), report, osc, CheckExif)
						osc.LogInfo(fmt.Sprintf("\t Found internal image %s\n", imageUrl))
					} else {
						osc.LogInfo(fmt.Sprintf("\t Not scanning remote image %s\n", imageUrl))
					}
				}
			}
		}

		osc.LogInfo("\tScanning for CSS Fonts and Background Images\n")
		utils.RemoveDuplicates(&cssLinks)
		for _, cssUrl := range cssLinks {
			osc.LogInfo(fmt.Sprintf("\tScanning CSS file: %s\n", cssUrl))
			_, cssContents, _ := scan.ScrapePage(report.HiddenService, utils.WithoutProtocol(cssUrl))
			domains = append(domains, utils.ExtractDomains(string(cssContents))[:]...)
		}

		osc.LogInfo("\tScanning for Links\n")
		domains = append(domains, utils.ExtractDomains(contents)...)
		utils.RemoveDuplicates(&domains)
		for _, domain := range domains {
			baseUrl, err := url.Parse(domain)
			if err == nil {
				if baseUrl.Host != "" && utils.WithoutSubdomains(baseUrl.Host) != utils.WithoutSubdomains(report.HiddenService) {
					osc.LogInfo(fmt.Sprintf("Found Related URL %s\n", domain))
					// TODO: Lots of information here which needs to be processed.
					// * Links to standard sites - google / bitpay etc.
					// * Links to other onion sites
					// * Links to obscure clearnet sites.
					report.AddLinkedSite(baseUrl.Host)
				} else {
					// * Process FQDN internal links
					osc.LogInfo(fmt.Sprintf("Found Internal URL %s\n", domain))
					report.AddInternalPage(baseUrl.Host)
				}
			}
		}

		osc.LogInfo("\tScanning for Referenced Directories\n")
		r := regexp.MustCompile("(src|href)=\"([^\"]*)\"")
		foundPaths := r.FindAllStringSubmatch(string(contents), -1)
		for _, regexpResults := range foundPaths {
			path := regexpResults[2]
			if (strings.HasPrefix(path, "http") || strings.HasPrefix(path, "//")) && !strings.Contains(path, utils.WithoutSubdomains(report.HiddenService)) {
				continue
			}

			term := strings.LastIndex(path, "/")
			if term > 0 {
				osc.LogInfo(fmt.Sprintf("\t Found Referenced Directory %s\n", path[:term]))
				report.AddPageReferencedDirectory(utils.WithoutProtocol(path[:term]))
			}
		}
	} else if status == 403 {
		osc.LogInfo(fmt.Sprintf("\tPage %s%s is Forbidden\n", report.HiddenService, page))
	} else if status == 404 {
		osc.LogInfo(fmt.Sprintf("\tPage %s%s is Does Not Exist\n", report.HiddenService, page))
	}
}
