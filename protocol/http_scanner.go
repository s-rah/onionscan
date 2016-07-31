package protocol

import (
	"crypto/tls"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/scans"
	"github.com/s-rah/onionscan/utils"
	"h12.me/socks"
	"io/ioutil"
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

func (hps *HTTPProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionscanConfig, report *report.OnionScanReport) {

	// HTTP
	osc.LogInfo(fmt.Sprintf("Checking %s http(80)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 80, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 80\n")
		report.WebDetected = false
		if conn != nil {
			conn.Close()
		}
	} else {
		osc.LogInfo("Found potential service on http(80)\n")
		report.WebDetected = true
		conn.Close()
		dialSocksProxy := socks.DialSocksProxy(socks.SOCKS5, osc.TorProxyAddress)
		transportConfig := &http.Transport{
			Dial:            dialSocksProxy,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		hps.Client = &http.Client{
			Transport: transportConfig,
		}
		// FIXME This should probably be moved to it's own file now.
		response, err := hps.Client.Get("http://" + hiddenService)
		if err == nil {
			// Reading all http headers
			osc.LogInfo(fmt.Sprintf("HTTP response headers: %s\n", report.ServerVersion))
			responseHeaders := response.Header
			for key := range responseHeaders {
				value := responseHeaders.Get(key)
				// normalize by strings.ToUpper(key) to avoid case sensitive checking
				report.AddResponseHeader(strings.ToUpper(key), value)
			}

			report.ServerVersion = responseHeaders.Get("Server")
			response.Body.Close()
		} else {
			osc.LogError(err)
		}

		// Apache mod-status Check
		hps.ScanPage(hiddenService, "/", report, osc, scans.StandardPageScan)
		hps.ScanPage(hiddenService, "/server-status", report, osc, scans.ApacheModStatus)
		hps.ScanPage(hiddenService, "/private_key", report, osc, scans.PrivateKeyScan)

		if osc.Fingerprint == false {
			osc.LogInfo("\tScanning Common and Referenced Directories\n")
			directories := append(CommonDirectories, report.PageReferencedDirectories...)
			utils.RemoveDuplicates(&directories)

			for _, directory := range directories {
				hps.ScanPage(hiddenService, directory, report, osc, scans.CheckDirectoryListing(osc.DirectoryDepth))
			}
		}
	}
}

func (hps *HTTPProtocolScanner) ScanPage(hiddenService string, page string, report *report.OnionScanReport, osc *config.OnionscanConfig, f func(scans.Scanner, string, int, string, *report.OnionScanReport, *config.OnionscanConfig)) {
	err, contents, responseCode := hps.ScrapePage(hiddenService, page)
	if err == nil {
		f(hps, page, responseCode, string(contents), report, osc)
		return
	} else {
		osc.LogError(err)
	}
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
		return err, nil, -1
	}
	defer response.Body.Close()
	contents, _ := ioutil.ReadAll(response.Body)
	return nil, contents, response.StatusCode
}
