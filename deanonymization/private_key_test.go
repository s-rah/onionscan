package deanonymization

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/crawldb"
	"github.com/s-rah/onionscan/model"
	"github.com/s-rah/onionscan/report"
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
	ctx.dbdir = "/tmp/test-crawl"
	os.RemoveAll(ctx.dbdir)

	ctx.osreport = report.NewOnionScanReport(ctx.onion)
	ctx.report = new(report.AnonymityReport)
	ctx.osc = new(config.OnionScanConfig)
	ctx.osc.Database = new(crawldb.CrawlDB)
	ctx.osc.Database.NewDB(ctx.dbdir)

	return ctx
}

func (ctx *EnvContext) CreatePage(filename string, status int, content_type string, content string) {
	page := new(model.Page)
	page.Status = status
	page.Headers = make(http.Header)
	page.Headers.Add("Content-Type", content_type)
	page.Snapshot = content
	id, err := ctx.osc.Database.InsertCrawlRecord("http://"+ctx.onion+filename, page)
	if err != nil {
		ctx.t.Error(fmt.Sprintf("Error inserting test document: %s", err))
	}
	ctx.osreport.Crawls[filename] = id
}

func (ctx *EnvContext) Cleanup() {
	defer os.RemoveAll(ctx.dbdir)
}

func TestPrivateKey(t *testing.T) {
	ctx := CreateEnvContext(t)
	defer ctx.Cleanup()

	// Test 1: no /private_key file
	PrivateKey(ctx.osreport, ctx.report, ctx.osc)

	if ctx.report.PrivateKeyDetected {
		t.Error(fmt.Sprintf("Nothing crawled: Should not have detected a private key"))
	}

	// Test 2: /private_key file with nonsense
	ctx.CreatePage("/private_key", 200, "text/plain", "private nonsense")
	PrivateKey(ctx.osreport, ctx.report, ctx.osc)

	if ctx.report.PrivateKeyDetected {
		t.Error(fmt.Sprintf("Should not have detected a private key"))
	}

	// Test 3: /private_key with actual key, intermixed with mess
	// below contains private key for ktjts6vcmrumyy5x.onion
	ctx.CreatePage("/r00t/private_key", 200, "text/plain", `
Gx6KF7pYhv+3cDbXDkDEAD3CW71BQDIIzCggI7xJSdNE5Q==
-----BEGIN RSA PRIVATE KEY-----
Gx6KF7pYhv+3cDbXDkDEAD3CW71BQDIIzCggI7xJSdNE5Q==
1234123141312412131
-----END RSA PRIVATE KEY-----
3424234
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDFbrAFB+piFsf+nEqcF4Vya+iUXKiYoLbxYvbUSAAaF1dSY9VT
IY43SPw2c4Nrlhf+6j2zvFIii6wCtYAkUwG0O1ySia/UMNmsaFXmwT3sh2iK9EsZ
GLgau9/zV11NmFTo4kHXfs0/459P55zxiVYtZLacEUNbdWB+uWk87wn0zwIDAQAB
AoGBAJrpFJd99HvuYBH409nR4tU6sgzm/ypyv9h6zC0YKWxPcCanSpSluY7LZ4nZ
7P4XkNBlPvCuDMwqR1cAzoCx2J0O8p1yU0eUlqNFTfBhghsumKf9VK8wFkKRXAJ1
XPUIMZTwfyd2LbOttlW9ItcdrVdKsg4SSNk/cj2QGg3Eu7AxAkEA6nGq3YauEpek
bE0MrEcEeAqa+FEHdJ4iu3Y7F1i0I7r3puzIzBSzgHxH7AEyQjf24KewmEJaytli
UJYqpA8Y0wJBANeV14IFE2ZnbgMtdGpcnK7vlT9uVQt+8pjRusrMlJImb/3jYWmu
iFPprDGIHG5qU/zlyMqV6Mc51L0PqM5sNpUCQQCP44mqAsINuTJ6IeP4THIKtv+c
DidURMYuZgcochHFqDfdJJCs6LuuzRhbWfSdvblw8pqpKHiO7VKxASlUnctvAkEA
1ok01xy5+5Q99EeNrDLRcXzWJzNiynfgb5d2rU39I5vAowVd8U9QN0E4rGno8TA6
uFbrBD8+UNQKEsK8l/80KQJAJWVcRYApxS/tqvnv99aJNvMZBGWgc8S+Jb5s52yS
Gx6KF7pYhv+3cDbXDkDEAD3CW71BQDIIzCggI7xJSdNE5Q==
-----END RSA PRIVATE KEY-----
1234123141312412131
3424234
uFbrBD8+UNQKEsK8l/80KQJAJWVcRYApxS/tqvnv99aJNvMZBGWgc8S+Jb5s52yS
Gx6KF7pYhv+3cDbXDkDEAD3CW71BQDIIzCggI7xJSdNE5Q==
`)
	PrivateKey(ctx.osreport, ctx.report, ctx.osc)

	if !ctx.report.PrivateKeyDetected {
		t.Error(fmt.Sprintf("Should have detected a private key"))
	}
}
