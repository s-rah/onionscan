package protocol

import (
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

func (hps *HTTPProtocolScanner) ScanProtocol(hiddenService string, proxyAddress string, report *report.OnionScanReport) {

	// HTTP
	log.Printf("Checking %s http(80)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, proxyAddress)("", hiddenService+":80")
	if err != nil {
		log.Printf("Failed to connect to service on port 80\n")
	} else {
		log.Printf("Found potential service on http(80)\n")
		report.WebDetected = true
		dialSocksProxy := socks.DialSocksProxy(socks.SOCKS5, proxyAddress)
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
			hps.ScanPage(hiddenService, directory, report, scans.CheckDirectoryListing)
		}
	}
	log.Printf("\n")
}

func (hps *HTTPProtocolScanner) ScanPage(hiddenService string, page string, report *report.OnionScanReport, f func(scans.Scanner, string, int, string, *report.OnionScanReport)) {
	response, err := hps.Client.Get("http://" + hiddenService + page)
	if err != nil {
		log.Printf("Error connecting to %s%s %s\n", hiddenService, page, err)
		return
	}
	defer response.Body.Close()
	contents, _ := ioutil.ReadAll(response.Body)
	f(hps, page, response.StatusCode, string(contents), report)
}
