package config

import (
	"github.com/s-rah/onionscan/crawldb"
	"log"
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
}

func Configure(torProxyAddress string, directoryDepth int, fingerprint bool, timeout int, database string, scans []string, verbose bool) *OnionScanConfig {
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
