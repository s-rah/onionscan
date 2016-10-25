package deanonymization

import (
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"strings"
	"testing"
)

func TestExtractBitcoinAddress(t *testing.T) {
	ctx := CreateEnvContext(t)
	defer ctx.Cleanup()

	// Test 1
	ExtractBitcoinAddress(ctx.osreport, ctx.report, ctx.osc)

	if len(ctx.report.BitcoinAddresses) > 0 {
		t.Errorf("Nothing crawled: Should not have detected a bitcoin address")
	}

	// Test 2: P2PKH bitcoin address
	ctx.CreatePage("/index.html", 200, "text/html", "<html><body>1CFCJHzSAC12VaJt2s1BwXgpb6beo9yWZU</body></html>")
	ExtractBitcoinAddress(ctx.osreport, ctx.report, ctx.osc)

	if len(ctx.report.BitcoinAddresses) != 1 {
		t.Errorf("Should have detected a bitcoin address")
	}
	if ctx.report.BitcoinAddresses[0] != "1CFCJHzSAC12VaJt2s1BwXgpb6beo9yWZU" {
		t.Errorf("Unexpected bitcoin address found")
	}

	// Test 3: P2SH (BIP13) bitcoin address
	ctx.report.BitcoinAddresses = []string{}
	ctx.CreatePage("/index.html", 200, "text/html", "<html><body>342ftSRCvFHfCeFFBuz4xwbeqnDw6BGUey</body></html>")
	ExtractBitcoinAddress(ctx.osreport, ctx.report, ctx.osc)

	if len(ctx.report.BitcoinAddresses) != 1 {
		t.Errorf("Should have detected a bitcoin address")
	}
	if ctx.report.BitcoinAddresses[0] != "342ftSRCvFHfCeFFBuz4xwbeqnDw6BGUey" {
		t.Errorf("Unexpected bitcoin address found")
	}

	// Test 4: Multiple addresses
	ctx.report.BitcoinAddresses = []string{}
	data, err := ioutil.ReadFile("testdata/bitcoin.html")
	if err != nil {
		t.Errorf("Error reading test html")
	}
	ctx.CreatePage("/index.html", 200, "text/html", string(data))
	ExtractBitcoinAddress(ctx.osreport, ctx.report, ctx.osc)

	if len(ctx.report.BitcoinAddresses) != 100 {
		t.Errorf("Should have detected 100 bitcoin addresses")
	}
	h := sha256.Sum256([]byte(strings.Join(ctx.report.BitcoinAddresses, " ")))
	if hex.EncodeToString(h[:]) != "aec30c5af50a875042af908cf483170e03c85207d70ffbef7401d1633a69bbdb" {
		t.Errorf("Address misdetection somewhere in testdata/bitcoin.html")
	}
}
