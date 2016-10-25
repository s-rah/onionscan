package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"golang.org/x/crypto/openpgp"
	"regexp"
	"strings"
)

// PGPContentScan extracts any PGP public key blobs that may exist in the current
// scan.
func PGPContentScan(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {

	pgpRegexp := regexp.MustCompile("-----BEGIN PGP PUBLIC KEY BLOCK-----((?s).*)-----END PGP PUBLIC KEY BLOCK-----")

	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {
			foundPGP := pgpRegexp.FindAllString(crawlRecord.Page.Snapshot, -1)
			for _, keyString := range foundPGP {
				keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(keyString))
				if err != nil {
					continue
				}
				if len(keys) < 1 || len(keys[0].Subkeys) < 1 || len(keys[0].Identities) < 1 {
					continue
				}

				var identity string
				for identity = range keys[0].Identities {
					anonreport.EmailAddresses = append(anonreport.EmailAddresses, identity)
					osc.Database.InsertRelationship(osreport.HiddenService, "pgp", "email-address", identity)
					break
				}

				osreport.AddPGPKey(keyString, identity, keys[0].Subkeys[0].PublicKey.KeyIdShortString())

				osc.Database.InsertRelationship(osreport.HiddenService, "pgp", "identity", keys[0].Subkeys[0].PublicKey.KeyIdShortString())
			}
		}
	}
}
