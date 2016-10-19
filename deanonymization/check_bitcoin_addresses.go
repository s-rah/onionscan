package deanonymization

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"regexp"
	"strings"
)

// A25 is a type for a 25 byte (not base58 encoded) bitcoin address.
type A25 [25]byte

// Version extracts the version byte from a bitcoin address
func (a *A25) Version() byte {
	return a[0]
}

// EmbeddedChecksum returns the checksum of a bitcoin address
func (a *A25) EmbeddedChecksum() (c [4]byte) {
	copy(c[:], a[21:])
	return
}

// DoubleSHA256 computes a double sha256 hash of the first 21 bytes of the
// address.  This is the one function shared with the other bitcoin RC task.
// Returned is the full 32 byte sha256 hash.  (The bitcoin checksum will be
// the first four bytes of the slice.)
func (a *A25) doubleSHA256() []byte {
	h := sha256.New()
	h.Write(a[:21])
	d := h.Sum([]byte{})
	h = sha256.New()
	h.Write(d)
	return h.Sum(d[:0])
}

// ComputeChecksum returns a four byte checksum computed from the first 21
// bytes of the address.  The embedded checksum is not updated.
func (a *A25) ComputeChecksum() (c [4]byte) {
	copy(c[:], a.doubleSHA256())
	return
}

// Tmpl and Set58 are adapted from the C solution.
// Go has big integers but this techinique seems better.
var tmpl = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// Set58 takes a base58 encoded address and decodes it into the receiver.
// Errors are returned if the argument is not valid base58 or if the decoded
// value does not fit in the 25 byte address.  The address is not otherwise
// checked for validity.
func (a *A25) Set58(s []byte) error {
	for _, s1 := range s {
		c := bytes.IndexByte(tmpl, s1)
		if c < 0 {
			return errors.New("bad char")
		}
		for j := 24; j >= 0; j-- {
			c += 58 * int(a[j])
			a[j] = byte(c % 256)
			c /= 256
		}
		if c > 0 {
			return errors.New("too long")
		}
	}
	return nil
}

// ValidA58 validates a base58 encoded bitcoin address.  An address is valid
// if it can be decoded into a 25 byte address, the version number is 0
// (P2PKH) or 5 (P2SH), and the checksum validates.  Return value ok will be
// true for valid addresses.  If ok is false, the address is invalid and the
// error value may indicate why.
func ValidA58(a58 []byte) (ok bool) {
	var a A25
	if err := a.Set58(a58); err != nil {
		return false
	}
	if a.Version() != 0 && a.Version() != 5 {
		return false
	}
	return a.EmbeddedChecksum() == a.ComputeChecksum()
}

// ExtractBitcoinAddress extracts any information related to bitcoin addresses from the current crawl.
func ExtractBitcoinAddress(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {
	bcaregex := regexp.MustCompile(`[13][a-km-zA-HJ-NP-Z1-9]{25,34}`)
	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {
			foundBCID := bcaregex.FindAllString(crawlRecord.Page.Snapshot, -1)
			for _, result := range foundBCID {
				if ValidA58([]byte(result)) {
					anonreport.BitcoinAddresses = append(anonreport.BitcoinAddresses, result)
					osc.Database.InsertRelationship(osreport.HiddenService, "snapshot", "bitcoin-address", result)
				}
			}
		}
	}
}
