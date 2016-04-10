package main

import (
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/scans"
	"h12.me/socks"
	"io/ioutil"
	"log"
	"net/http"
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

	report := report.NewOnionScanReport(hiddenService)

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
