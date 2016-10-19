package config

import (
	"bufio"
	"fmt"
	"github.com/s-rah/onionscan/crawldb"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OnionScanConfig defines options to tweak the overall OnionScan system.
type OnionScanConfig struct {
	TorProxyAddress string
	Depth           int
	Fingerprint     bool
	Timeout         time.Duration
	Verbose         bool
	Database        *crawldb.CrawlDB
	RescanDuration  time.Duration
	Scans           []string
	CrawlConfigs    map[string]CrawlConfig
	Cookies         []*http.Cookie
}

// Configure creates a new OnionScanConfig object with a set of options.
// FIXME: We can make this a decorate and make it much nicer.
func Configure(torProxyAddress string, directoryDepth int, fingerprint bool, timeout int, database string, scans []string, crawlconfigdir string, cookie string, verbose bool) *OnionScanConfig {
	osc := new(OnionScanConfig)
	osc.TorProxyAddress = torProxyAddress
	osc.Depth = directoryDepth
	osc.Fingerprint = fingerprint
	osc.Timeout = time.Duration(time.Second * time.Duration(timeout))
	osc.Verbose = verbose
	osc.Database = new(crawldb.CrawlDB)
	osc.Database.NewDB(database)
	osc.RescanDuration = time.Hour * -100
	osc.Scans = scans
	osc.CrawlConfigs = make(map[string]CrawlConfig)

	rawRequest := fmt.Sprintf("GET / HTTP/1.0\r\nCookie: %s\r\n\r\n", cookie)

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))

	if err == nil {
		osc.Cookies = req.Cookies()
	}

	visit := func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			cc, err := LoadCrawlConfig(path)
			if err == nil {
				osc.LogInfo(fmt.Sprintf("Loading Crawl Config for %s %v", cc.Onion, cc))
				osc.CrawlConfigs[cc.Onion] = cc
			} else {
				osc.LogError(err)
			}
		}
		return nil
	}

	if crawlconfigdir != "" {
		filepath.Walk(crawlconfigdir, visit)
	}

	return osc
}

// LogInfo logs an informational message to the log, assuming that the log level
// is set low enough.
func (os *OnionScanConfig) LogInfo(message string) {
	if os.Verbose {
		log.Printf("INFO: %v", message)
	}
}

// LogError logs an error message to the log, always.
func (os *OnionScanConfig) LogError(err error) {
	log.Printf("ERROR: %v", err)
}
