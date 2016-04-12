package main

import (
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/scans"
	"h12.me/socks"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type OnionScan struct {
	TorProxyAddress string
	Client          *http.Client
}

func Configure(torProxyAddress string) *OnionScan {
	onionScan := new(OnionScan)
	onionScan.TorProxyAddress = torProxyAddress
	dialSocksProxy := socks.DialSocksProxy(socks.SOCKS5, onionScan.TorProxyAddress)
	transportConfig := &http.Transport{
		Dial: dialSocksProxy,
	}
	onionScan.Client = &http.Client{Transport: transportConfig}
	return onionScan
}

func (os *OnionScan) Scan(hiddenService string) (*report.OnionScanReport, error) {

	// Remove Extra Prefix
	// TODO: Add support for HTTPS?
	if strings.HasPrefix(hiddenService, "http://") {
		hiddenService = hiddenService[7:]
	}

	if strings.HasSuffix(hiddenService, "/") {
		hiddenService = hiddenService[0 : len(hiddenService)-1]
	}

	report := report.NewOnionScanReport(hiddenService)

	// It's Port Scanning Time.
	log.Printf("Checking %s ssh(22)\n", hiddenService)
	_, err := socks.DialSocksProxy(socks.SOCKS5, os.TorProxyAddress)("", hiddenService+":22")
	if err != nil {
		log.Printf("Failed to connect to service on port 22\n")
	} else {
		// TODO SSH Checking
	}

	log.Printf("Checking %s http(80)\n", hiddenService)
	// It's Port Scanning Time.
	_, err = socks.DialSocksProxy(socks.SOCKS5, os.TorProxyAddress)("", hiddenService+":80")
	if err != nil {
		log.Printf("Failed to connect to service on port 80\n")
	} else {
		// FIXME This should probably be moved to it's own file now.
		response, err := os.Client.Get("http://" + hiddenService)

		if err != nil {
			return report, err
		}

		// Initial Attempt at Resolving Server Type
		log.Printf("Attempting to Derive Server Type from Headers..\n")
		report.ServerVersion = response.Header.Get("Server")
		log.Printf("\tServer Version: %s\n", report.ServerVersion)

		// Apache mod-status Check
		os.ScanPage(hiddenService, "/server-status", report, scans.ApacheModStatus)
		os.ScanPage(hiddenService, "/", report, scans.StandardPageScan)

		os.ScanPage(hiddenService, "/style", report, scans.CheckDirectoryListing)
		os.ScanPage(hiddenService, "/styles", report, scans.CheckDirectoryListing)
		os.ScanPage(hiddenService, "/css", report, scans.CheckDirectoryListing)
		os.ScanPage(hiddenService, "/uploads", report, scans.CheckDirectoryListing)
		os.ScanPage(hiddenService, "/images", report, scans.CheckDirectoryListing)
		os.ScanPage(hiddenService, "/img", report, scans.CheckDirectoryListing)
		os.ScanPage(hiddenService, "/static", report, scans.CheckDirectoryListing)

		// Lots of Wordpress installs which don't lock down directory listings
		os.ScanPage(hiddenService, "/wp-content/uploads", report, scans.CheckDirectoryListing)

		// Common with torshops created onions
		os.ScanPage(hiddenService, "/products", report, scans.CheckDirectoryListing)
		os.ScanPage(hiddenService, "/products/cat", report, scans.CheckDirectoryListing)
	}

	return report, nil
}

func (os *OnionScan) ScanPage(hiddenService string, page string, report *report.OnionScanReport, f func(scans.Scanner, string, int, string, *report.OnionScanReport)) {
	response, err := os.Client.Get("http://" + hiddenService + page)
	if err != nil {
		log.Printf("Error connecting to %s%s %s\n", hiddenService, page, err)
		return
	}
	defer response.Body.Close()
	contents, _ := ioutil.ReadAll(response.Body)
	f(os, page, response.StatusCode, string(contents), report)
}
