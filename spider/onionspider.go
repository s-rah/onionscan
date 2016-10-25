package spider

import (
	"crypto/tls"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/model"
	"github.com/s-rah/onionscan/report"
	"golang.org/x/net/proxy"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

type OnionSpider struct {
	client *http.Client
}

func (os *OnionSpider) Crawl(hiddenservice string, osc *config.OnionScanConfig, report *report.OnionScanReport) {

	torDialer, err := proxy.SOCKS5("tcp", osc.TorProxyAddress, nil, proxy.Direct)

	if err != nil {
		osc.LogError(err)
	}

	basepath := osc.CrawlConfigs[hiddenservice].Base
	if basepath == "" {
		basepath = "/"
	}

	base, err := url.Parse("http://" + hiddenservice + basepath)

	if err != nil {
		osc.LogError(err)
		return
	}

	transportConfig := &http.Transport{
		Dial:            torDialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	cookieJar, _ := cookiejar.New(nil)
	cookieJar.SetCookies(base, osc.Cookies)

	os.client = &http.Client{
		Transport: transportConfig,
		Jar:       cookieJar,
	}

	addCrawl := func(uri string, id int, err error) {
		if err == nil {
			report.Crawls[uri] = id
		} else {
			osc.LogError(err)
		}
	}

	// Extract interesting details from the first page
	result, id := osc.Database.HasCrawlRecord(base.String(), osc.RescanDuration)
	if result {
		osc.LogInfo("Already crawled URL recently - reusing existing crawl")
		report.Crawls[base.String()] = id
	} else {
		osc.LogInfo(fmt.Sprintf("Starting to Scan Page: %s", base.String()))
		id, err = os.GetPage(base.String(), base, osc, true)
		addCrawl(base.String(), id, err)
	}

	var scanDir func(string)
	scanDir = func(uri string) {
		resourceURI, err := url.Parse(uri)
		if err == nil {
			term := strings.LastIndex(resourceURI.Path, "/")

			if term > 0 {
				if term == len(resourceURI.Path)-1 {
					term = strings.LastIndex(resourceURI.Path[len(resourceURI.Path)-2:], "/")
				}

				potentialDirectory := NormalizeURI(resourceURI.Path[:term], base)
				_, exists := report.Crawls[potentialDirectory]
				if !exists {
					result, cid := osc.Database.HasCrawlRecord(potentialDirectory, osc.RescanDuration)
					if !result {
						osc.LogInfo(fmt.Sprintf("Scanning Directory: %s", potentialDirectory))
						id, err := os.GetPage(potentialDirectory, base, osc, false)
						addCrawl(potentialDirectory, id, err)
						scanDir(potentialDirectory)
					} else {
						osc.LogInfo(fmt.Sprintf("Already crawled %s (%s) recently - reusing existing crawl", resourceURI.Path[:term], potentialDirectory))
						addCrawl(potentialDirectory, cid, nil)
					}
				}
			}
		}
	}

	processURI := func(uri string, base *url.URL) {
		target, err := url.Parse(uri)
		if err == nil && base.Host == target.Host {
			normalizeTarget := NormalizeURI(target.String(), base)
			_, exists := report.Crawls[normalizeTarget]
			if strings.HasPrefix(target.Path, base.Path) && !exists {
				result, cid := osc.Database.HasCrawlRecord(normalizeTarget, osc.RescanDuration)
				if !result {
					osc.LogInfo(fmt.Sprintf("Scanning URI: %s", target.String()))
					id, err := os.GetPage(normalizeTarget, base, osc, true)
					addCrawl(normalizeTarget, id, err)
					scanDir(normalizeTarget)
				} else {
					osc.LogInfo(fmt.Sprintf("Already crawled %s (%s) recently - reusing existing crawl", target.String(), normalizeTarget))
					addCrawl(normalizeTarget, cid, nil)
				}
			}
		}
	}

	exclude := func(uri string) bool {
		for _, rule := range osc.CrawlConfigs[hiddenservice].Exclude {
			if strings.Contains(uri, rule) {
				return true
			}
		}
		return false
	}

	// Grab Server Status if it Exists
	// We add it as a resource so we can pull any information out of it later.
	mod_status, _ := url.Parse("http://" + hiddenservice + "/server-status")
	osc.LogInfo(fmt.Sprintf("Scanning URI: %s", mod_status.String()))
	id, err = os.GetPage(mod_status.String(), base, osc, true)
	addCrawl(mod_status.String(), id, err)

	// Grab Private Key if it Exists
	// This would be a major security fail
	private_key, _ := url.Parse("http://" + hiddenservice + "/private_key")
	osc.LogInfo(fmt.Sprintf("Scanning URI: %s", private_key.String()))
	id, err = os.GetPage(private_key.String(), base, osc, true)
	addCrawl(private_key.String(), id, err)

	processed := make(map[string]bool)

	// The rest of the site
	for i := 0; i < osc.Depth; i++ {
		// Process all the images we can find
		osc.LogInfo(fmt.Sprintf("Scanning Depth: %d", i))

		// Copy to Prevent Map Updating from Influencing Depth
		crawlMap := make(map[string]int)
		for k, v := range report.Crawls {
			crawlMap[k] = v
		}

		for url, id := range crawlMap {
			_, exists := processed[url]
			if !exists {
				crawlRecord, _ := osc.Database.GetCrawlRecord(id)
				for _, image := range crawlRecord.Page.Images {
					if !exclude(image.Target) {
						processURI(image.Target, base)
					}
				}

				for _, anchor := range crawlRecord.Page.Anchors {
					if !exclude(anchor.Target) {
						processURI(anchor.Target, base)
					}
				}

				for _, link := range crawlRecord.Page.Links {
					if !exclude(link.Target) {
						processURI(link.Target, base)
					}
				}

				for _, script := range crawlRecord.Page.Scripts {
					if !exclude(script.Target) {
						processURI(script.Target, base)
					}
				}
				processed[url] = true
			}

		}
	}
}

func (os *OnionSpider) GetPage(uri string, base *url.URL, osc *config.OnionScanConfig, snapshot bool) (int, error) {
	response, err := os.client.Get(uri)

	// Sometimes Weird Things Happen
	if err != nil {
		page := model.Page{}
		page.Status = -1
		page.Snapshot = err.Error()
		id, err := osc.Database.InsertCrawlRecord(uri, &page)
		return id, err
	}

	defer response.Body.Close()
	page := model.Page{}
	if strings.Contains(response.Header.Get("Content-Type"), "text/html") {
		page = ParsePage(response.Body, base, snapshot)
		osc.LogInfo(fmt.Sprintf("Grabbed %d byte document", len(page.Snapshot)))
	} else if strings.Contains(response.Header.Get("Content-Type"), "image/jpeg") {
		page = SnapshotBinaryResource(response.Body)
		osc.LogInfo(fmt.Sprintf("Fetched %d byte image", len(page.Raw)))
	} else if snapshot {
		page = SnapshotResource(response.Body)
		osc.LogInfo(fmt.Sprintf("Grabbed %d byte document", len(page.Snapshot)))
	} else {
		osc.LogInfo(fmt.Sprintf("Content type of %s does not have a special handler: %v - minimal data will be collected", uri, response.Header["Content-Type"]))
	}

	page.Status = response.StatusCode
	page.Headers = response.Header
	id, err := osc.Database.InsertCrawlRecord(uri, &page)
	return id, err
}
