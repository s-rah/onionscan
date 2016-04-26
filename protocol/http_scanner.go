package protocol

import (
	"github.com/s-rah/onionscan/scans"
	"github.com/s-rah/onionscan/report"
	"net/http"
	"io/ioutil"
	"h12.me/socks"
	"log"
)

type HTTPProtocolScanner struct {
	Client          *http.Client
}

func (hps * HTTPProtocolScanner) ScanProtocol(hiddenService string, proxyAddress string, report *report.OnionScanReport) {

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

		// Initial Attempt at Resolving Server Type
		log.Printf("Attempting to Derive Server Type from Headers..\n")
		report.ServerVersion = response.Header.Get("Server")
		log.Printf("\tServer Version: %s\n", report.ServerVersion)

		// Apache mod-status Check
		hps.ScanPage(hiddenService, "/server-status", report, scans.ApacheModStatus)
		hps.ScanPage(hiddenService, "/", report, scans.StandardPageScan)

		hps.ScanPage(hiddenService, "/style", report, scans.CheckDirectoryListing)
		hps.ScanPage(hiddenService, "/styles", report, scans.CheckDirectoryListing)
		hps.ScanPage(hiddenService, "/css", report, scans.CheckDirectoryListing)
		hps.ScanPage(hiddenService, "/uploads", report, scans.CheckDirectoryListing)
		hps.ScanPage(hiddenService, "/images", report, scans.CheckDirectoryListing)
		hps.ScanPage(hiddenService, "/img", report, scans.CheckDirectoryListing)
		hps.ScanPage(hiddenService, "/static", report, scans.CheckDirectoryListing)

		// Lots of Wordpress installs which don't lock down directory listings
		hps.ScanPage(hiddenService, "/wp-content/uploads", report, scans.CheckDirectoryListing)

		// Common with torshops created onions
		hps.ScanPage(hiddenService, "/products", report, scans.CheckDirectoryListing)
		hps.ScanPage(hiddenService, "/products/cat", report, scans.CheckDirectoryListing)
	}
	log.Printf("\n")
}

func (hps * HTTPProtocolScanner) ScanPage(hiddenService string, page string, report *report.OnionScanReport, f func(scans.Scanner, string, int, string, *report.OnionScanReport)) {
	response, err := hps.Client.Get("http://" + hiddenService + page)
	if err != nil {
		log.Printf("Error connecting to %s%s %s\n", hiddenService, page, err)
		return
	}
	defer response.Body.Close()
	contents, _ := ioutil.ReadAll(response.Body)
	f(hps, page, response.StatusCode, string(contents), report)
}
