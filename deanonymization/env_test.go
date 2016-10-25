package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/crawldb"
	"github.com/s-rah/onionscan/model"
	"github.com/s-rah/onionscan/report"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

type EnvContext struct {
	t        *testing.T
	osreport *report.OnionScanReport
	report   *report.AnonymityReport
	osc      *config.OnionScanConfig
	dbdir    string
	onion    string
}

func CreateEnvContext(t *testing.T) *EnvContext {
	ctx := new(EnvContext)
	ctx.t = t
	ctx.onion = "ktjts6vcmrumyy5x.onion"
	var err error
	ctx.dbdir, err = ioutil.TempDir("", "test-crawl")
	if err != nil {
		ctx.t.Errorf("Error creating temporary directory: %s", err)
	}

	ctx.osreport = report.NewOnionScanReport(ctx.onion)
	ctx.report = new(report.AnonymityReport)
	ctx.osc = new(config.OnionScanConfig)
	ctx.osc.Database = new(crawldb.CrawlDB)
	ctx.osc.Database.NewDB(ctx.dbdir)

	return ctx
}

func (ctx *EnvContext) CreatePage(filename string, status int, contentType string, content string) {
	page := new(model.Page)
	page.Status = status
	page.Headers = make(http.Header)
	page.Headers.Add("Content-Type", contentType)
	page.Snapshot = content
	id, err := ctx.osc.Database.InsertCrawlRecord("http://"+ctx.onion+filename, page)
	if err != nil {
		ctx.t.Errorf("Error inserting test document: %s", err)
	}
	ctx.osreport.Crawls[filename] = id
}

func (ctx *EnvContext) CreateBinaryPage(filename string, status int, contentType string, content []byte) {
	page := new(model.Page)
	page.Status = status
	page.Headers = make(http.Header)
	page.Headers.Add("Content-Type", contentType)
	page.Raw = content
	id, err := ctx.osc.Database.InsertCrawlRecord("http://"+ctx.onion+filename, page)
	if err != nil {
		ctx.t.Errorf("Error inserting test document: %s", err)
	}
	ctx.osreport.Crawls[filename] = id
}

func (ctx *EnvContext) Cleanup() {
	os.RemoveAll(ctx.dbdir)
}
