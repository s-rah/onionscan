package scans

import (
	"crypto/sha1"
	"encoding/hex"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"golang.org/x/net/html"
	"log"
	"net/url"
	"regexp"
	"strings"
)

func StandardPageScan(scan Scanner, page string, status int, contents string, report *report.OnionScanReport) {
	log.Printf("Scanning %s\n", page)
	if status == 200 {
		log.Printf("\tPage %s is Accessible\n", page)

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

		log.Printf("\tScanning for Images\n")
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

				baseUrl, _ := url.Parse(imageUrl)
				if utils.WithoutSubdomains(baseUrl.Host) == utils.WithoutSubdomains(report.HiddenService) {
					scan.ScanPage(report.HiddenService, utils.WithoutProtocol(imageUrl), report, CheckExif)
					log.Printf("\t Found internal image %s\n", imageUrl)
				} else {
					log.Printf("\t Not scanning remote image %s\n", imageUrl)
				}
			}
		}

		log.Printf("\tScanning for CSS Fonts and Background Images\n")
		for _, cssUrl := range cssLinks {
			log.Printf("\tScanning CSS file: %s\n", cssUrl)
			_, cssContents, _ := scan.ScrapePage(report.HiddenService, utils.WithoutProtocol(cssUrl))
			domains = append(domains, utils.ExtractDomains(string(cssContents))[0:]...)
		}

		log.Printf("\tScanning for Links\n")
		domains = append(domains, utils.ExtractDomains(contents)...)
		for _, domain := range domains {
			baseUrl, _ := url.Parse(domain)
			if baseUrl.Host != "" && utils.WithoutSubdomains(baseUrl.Host) != utils.WithoutSubdomains(report.HiddenService) {
				log.Printf("Found Related URL %s\n", domain)
				// TODO: Lots of information here which needs to be processed.
				// * Links to standard sites - google / bitpay etc.
				// * Links to other onion sites
				// * Links to obscure clearnet sites.
				report.AddLinkedSite(baseUrl.Host)
			} else {
				// * Process FQDN internal links
				log.Printf("Found Internal URL %s\n", domain)
				report.AddInternalPage(baseUrl.Host)
			}
		}

		log.Printf("\tScanning for Referenced Directories\n")
		r := regexp.MustCompile("(src|href)=\"([^\"]*)\"")
		foundPaths := r.FindAllStringSubmatch(string(contents), -1)
		for _, regexpResults := range foundPaths {
			path := regexpResults[2]
			if (strings.HasPrefix(path, "http") || strings.HasPrefix(path, "//")) && !strings.Contains(path, utils.WithoutSubdomains(report.HiddenService)) {
				continue
			}

			term := strings.LastIndex(path, "/")
			if term > 0 {
				log.Printf("\t Found Referenced Directory %s\n", path[:term])
				report.AddPageReferencedDirectory(utils.WithoutProtocol(path[:term]))
			}
		}
	} else if status == 403 {
		log.Printf("\tPage %s%s is Forbidden\n", report.HiddenService, page)
	} else if status == 404 {
		log.Printf("\tPage %s%s is Does Not Exist\n", report.HiddenService, page)
	}
}
