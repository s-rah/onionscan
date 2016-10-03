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

	transportConfig := &http.Transport{
		Dial:            torDialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	cookieJar, _ := cookiejar.New(nil)

	os.client = &http.Client{
		Transport: transportConfig,
		Jar:       cookieJar,
	}

	base, err := url.Parse("http://" + hiddenservice + "/")

	if err != nil {
		osc.LogError(err)
		return
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
				result, cid := osc.Database.HasCrawlRecord(potentialDirectory, osc.RescanDuration)
				if !result {
					osc.LogInfo(fmt.Sprintf("Scanning Directory: %s", potentialDirectory))
					id, err := os.GetPage(potentialDirectory, base, osc, false)
					addCrawl(potentialDirectory, id, err)
					scanDir(potentialDirectory)
				} else {
					osc.LogInfo(fmt.Sprintf("Already crawled %s recently - reusing existing crawl", potentialDirectory))
					addCrawl(potentialDirectory, cid, nil)
				}
			}
		}
	}

	processURI := func(uri string, base *url.URL) {
		target, err := url.Parse(uri)
		if err == nil && base.Host == target.Host {
			normalizeTarget := NormalizeURI(target.String(), base)
			if base.Path != target.Path {
				result, cid := osc.Database.HasCrawlRecord(normalizeTarget, osc.RescanDuration)
				if !result {
					osc.LogInfo(fmt.Sprintf("Scanning URI: %s", target.String()))
					id, err := os.GetPage(normalizeTarget, base, osc, false)
					addCrawl(normalizeTarget, id, err)
					scanDir(normalizeTarget)
				} else {
					osc.LogInfo(fmt.Sprintf("Already crawled %s recently - reusing existing crawl", normalizeTarget))
					addCrawl(normalizeTarget, cid, nil)
				}
			}
		}
	}

	// Grab Server Status if it Exists
	// We add it as a resource so we can pull any information out of it later.
	mod_status, _ := url.Parse("http://" + hiddenservice + "/server-status")
	id, err = os.GetPage(mod_status.String(), base, osc, true)
	addCrawl(mod_status.String(), id, err)

	// Grab Private Key if it Exists
	// This would be a major security fail
	private_key, _ := url.Parse("http://" + hiddenservice + "/private_key")
	id, err = os.GetPage(private_key.String(), base, osc, true)
	addCrawl(private_key.String(), id, err)

	processed := make(map[string]bool)

	// The rest of the site
	for i := 0; i < osc.Depth; i++ {
		// Process all the images we can find
		for url, id := range report.Crawls {
			_, exists := processed[url]
			if !exists {
				crawlRecord, _ := osc.Database.GetCrawlRecord(id)
				for _, image := range crawlRecord.Page.Images {
					processURI(image.Target, base)
				}

				for _, anchor := range crawlRecord.Page.Anchors {
					processURI(anchor.Target, base)
				}

				for _, link := range crawlRecord.Page.Links {
					processURI(link.Target, base)
				}

				for _, script := range crawlRecord.Page.Scripts {
					processURI(script.Target, base)
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
