package config

import (
	"fmt"
	"github.com/s-rah/onionscan/crawldb"
	"log"
	"os"
	"path/filepath"
	"time"
)

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
}

func Configure(torProxyAddress string, directoryDepth int, fingerprint bool, timeout int, database string, scans []string, crawlconfigdir string, verbose bool) *OnionScanConfig {
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

	visit := func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			cc, err := LoadCrawlConfig(path)
			if err == nil {
				osc.LogInfo(fmt.Sprintf("Loading Crawl Config for %s %v", cc.Onion, cc))
				osc.CrawlConfigs[cc.Onion] = cc
			}
		}
		return nil
	}

	if crawlconfigdir != "" {
		filepath.Walk(crawlconfigdir, visit)
	}

	return osc
}

func (os *OnionScanConfig) LogInfo(message string) {
	if os.Verbose {
		log.Printf("INFO: %v", message)
	}
}

func (os *OnionScanConfig) LogError(err error) {
	log.Printf("ERROR: %v", err)
}
