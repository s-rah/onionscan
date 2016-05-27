package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/scans"
	"github.com/s-rah/onionscan/utils"
	"h12.me/socks"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type HTTPProtocolScanner struct {
	Client *http.Client
}

var (
	CommonDirectories = []string{"/style", "/styles", "/css", "/uploads", "/images", "/img", "/static",
		// Lots of Wordpress installs which don't lock down directory listings
		"/wp-content/uploads",
		// Common with torshops created onions
		"/products", "/products/cat"}
)

func (hps *HTTPProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {

	// HTTP
	log.Printf("Checking %s http(80)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)("", hiddenService+":80")
	if err != nil {
		log.Printf("Failed to connect to service on port 80\n")
		report.WebDetected = false
		return
	} else {
		log.Printf("Found potential service on http(80)\n")
		report.WebDetected = true
		dialSocksProxy := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)
		transportConfig := &http.Transport{
			Dial: dialSocksProxy,
		}
		hps.Client = &http.Client{Transport: transportConfig}
		// FIXME This should probably be moved to it's own file now.
		response, err := hps.Client.Get("http://" + hiddenService)

		if err != nil {
			log.Printf("Failed to connect to service on port 80\n")
			return
		}

		// Reading all http headers
		log.Printf("HTTP response headers: %s\n", report.ServerVersion)
		responseHeaders := response.Header
		for key := range responseHeaders {
			value := responseHeaders.Get(key)
			// normalize by strings.ToUpper(key) to avoid case sensitive checking
			report.AddResponseHeader(strings.ToUpper(key), value)
			log.Printf("\t%s : %s\n", strings.ToUpper(key), value)
		}

		report.ServerVersion = responseHeaders.Get("Server")

		// Apache mod-status Check
		hps.ScanPage(hiddenService, "/server-status", report, scans.ApacheModStatus)
		hps.ScanPage(hiddenService, "/", report, scans.StandardPageScan)

		log.Printf("\tScanning Common and Referenced Directories\n")
		directories := append(CommonDirectories, report.PageReferencedDirectories...)
		utils.RemoveDuplicates(&directories)
		for _, directory := range directories {
			hps.ScanPage(hiddenService, directory, report, scans.CheckDirectoryListing(onionscanConfig.DirectoryDepth))
		}
	}
	log.Printf("\n")
}

func (hps *HTTPProtocolScanner) ScanPage(hiddenService string, page string, report *report.OnionScanReport, f func(scans.Scanner, string, int, string, *report.OnionScanReport)) {
	_, contents, responseCode := hps.ScrapePage(hiddenService, page)
	f(hps, page, responseCode, string(contents), report)
}

func (hps *HTTPProtocolScanner) ScrapePage(hiddenService string, page string) (error, []byte, int) {
	if !strings.Contains(page, utils.WithoutSubdomains(hiddenService)) {
		if !strings.HasPrefix(page, "/") {
			page = "/" + page
		}
		page = hiddenService + page
	}
	response, err := hps.Client.Get("http://" + page)
	if err != nil {
		log.Printf("Error connecting to http://%s %s\n", page, err)
		return err, nil, -1
	}
	defer response.Body.Close()
	contents, _ := ioutil.ReadAll(response.Body)
	return nil, contents, response.StatusCode
}
