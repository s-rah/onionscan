package protocol

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/crawldb"
	"github.com/s-rah/onionscan/report"
	"io/ioutil"
	"os"
	"testing"
)

// Quick mock hidden service check
func MockCheckHiddenService(t *testing.T, proxy *TestSOCKS5Server, ps Scanner, hiddenService string) *report.OnionScanReport {
	osc := new(config.OnionScanConfig)
	osc.TorProxyAddress = proxy.ListenAddress
	osc.Verbose = testing.Verbose()
	r := report.NewOnionScanReport(hiddenService)
	ps.ScanProtocol(hiddenService, osc, r)
	return r
}

// Full setup with database, this is much slower
func MockCheckHiddenServiceWithDatabase(t *testing.T, proxy *TestSOCKS5Server, ps Scanner, hiddenService string) *report.OnionScanReport {
	osc := new(config.OnionScanConfig)
	osc.TorProxyAddress = proxy.ListenAddress
	osc.Verbose = testing.Verbose()
	dbdir, err := ioutil.TempDir("", "test-crawl")
	if err != nil {
		t.Errorf("Error creating temporary directory: %s", err)
		return nil
	}
	defer os.RemoveAll(dbdir)
	osc.Database = new(crawldb.CrawlDB)
	osc.Database.NewDB(dbdir)

	r := report.NewOnionScanReport(hiddenService)
	ps.ScanProtocol(hiddenService, osc, r)

	return r
}
