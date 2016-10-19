package deanonymization

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"net/url"
	"regexp"
	"strings"
)

// PrivateKey extracts an exposed private key if it exists in the current crawl
func PrivateKey(osreport *report.OnionScanReport, report *report.AnonymityReport, osc *config.OnionScanConfig) {
	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)

		uri, _ := url.Parse(crawlRecord.URL)
		if crawlRecord.Page.Status == 200 && strings.HasSuffix(uri.Path, "/private_key") {
			privateKeyRegex := regexp.MustCompile("-----BEGIN RSA PRIVATE KEY-----((?s).*)-----END RSA PRIVATE KEY-----")
			foundPrivateKey := privateKeyRegex.FindAllString(crawlRecord.Page.Snapshot, -1)
			for _, keyString := range foundPrivateKey {
				osc.LogInfo(fmt.Sprintf("Found Potential Private Key"))
				block, _ := pem.Decode([]byte(keyString))
				if block == nil || block.Type != "RSA PRIVATE KEY" {
					osc.LogInfo("Could not parse privacy key: no valid PEM data found")
					continue
				}

				privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					osc.LogInfo("Could not parse private key")
					continue
				}

				// DER Encode the Public Key
				publicKeyBytes, _ := asn1.Marshal(rsa.PublicKey{
					N: privateKey.PublicKey.N,
					E: privateKey.PublicKey.E,
				})

				h := sha1.New()
				h.Write(publicKeyBytes)
				sha1bytes := h.Sum(nil)

				data := base32.StdEncoding.EncodeToString(sha1bytes)
				hostname := strings.ToLower(data[0:16])
				osc.LogInfo(fmt.Sprintf("Found Private Key for Host %s.onion", hostname))
				report.PrivateKeyDetected = true
			}
		}
	}
}
