package scans

import (
	"github.com/s-rah/onionscan/report"
	"golang.org/x/crypto/openpgp"
	"log"
	"regexp"
	"strings"
	"fmt"
)

type PGPContentScan struct {
}

func (cs *PGPContentScan) ScanContent(content string, report *report.OnionScanReport) {
	log.Printf("Scanning for PGP Key\n")
	pgpRegexp := regexp.MustCompile("-----BEGIN PGP PUBLIC KEY BLOCK-----((?s).*)-----END PGP PUBLIC KEY BLOCK-----")
	foundPGP := pgpRegexp.FindAllString(content, -1)
	for _, keyString := range foundPGP {
		keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(keyString));
		if err != nil {
			log.Printf("ERROR: %s\n", err)
			continue
		}
		if len(keys) < 1 || len(keys[0].Subkeys) < 1 || len(keys[0].Identities) < 1{
			log.Printf("ERROR: failed to accept key\n")
			continue
		}

		var identity string
		for identity, _ = range keys[0].Identities {
			break
		}
		var fingerprint string
		fingerprint = fmt.Sprintf("%X", keys[0].Subkeys[0].PublicKey.Fingerprint)
		log.Printf("\tFound PGP Key fingerprint: %s belonging to %s", fingerprint, identity)

		report.AddPGPKey(keyString, identity, fingerprint)
	}
}
