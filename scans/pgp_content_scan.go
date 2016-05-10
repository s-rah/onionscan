package scans

import (
	"github.com/s-rah/onionscan/report"
	"log"
	"regexp"
)

type PGPContentScan struct {
}

func (cs *PGPContentScan) ScanContent(content string, report *report.OnionScanReport) {
	log.Printf("\tScanning for PGP Key\n")
	pgpRegexp := regexp.MustCompile("-----BEGIN PGP PUBLIC KEY BLOCK-----((?s).*)-----END PGP PUBLIC KEY BLOCK-----")
	foundPGP := pgpRegexp.FindAllString(content, -1)
	for _, key := range foundPGP {
		report.AddPGPKey(key)
	}
}
