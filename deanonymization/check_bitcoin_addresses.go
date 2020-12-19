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

// Tmpl and Set58 are adapted from the C solution.
// Go has big integers but this techinique seems better.
var tmpl = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// ValidateA58 validates a base58 encoded bitcoin address.  An address is valid
// if it can be decoded into a 25 byte address, the version number is 0
// (P2PKH) or 5 (P2SH), and the checksum validates.  Return value ok will be
// true for valid addresses.  If ok is false, the address is invalid and the
// error value may indicate why.
func ValidateA58(a58 []byte) (ok bool) {
	a := make([]byte, 25)
	if err := Set58(a58, a); err != nil {
		return false
	}
	if Version(a) != 0 && Version(a) != 5 {
		return false
	}
	return EmbeddedChecksum(a) == ComputeChecksum(a)
}

// ValidateP58 validates a base58 encoded private key.  A private key is valid
// if it can be decoded into a 37 byte private key, start with a 0x80 byte,
// and the checksum validates.  Return value ok will be true for valid private keys.
// If ok is false, the private key is invalid and the error value may indicate why.
func ValidateP58(p58 []byte) (ok bool) {
	p := make([]byte, 37)
	if p58[0] != 'L' && p58[0] != 'K' {
		return false
	}
	if err := Set58(p58[1:], p); err != nil {
		return false
	}
	if Version(p) != 128 {
		return false
	}
	return EmbeddedChecksum(p) == ComputeChecksum(p)
}

// Set58 takes a base58 encoded string decodes it into a byte slice.
// Errors are returned if the argument is not a valid base58 or if the decoded
// value does not fit in the byte slice.
func Set58(s []byte, b []byte) error {
	for _, s1 := range s {
		c := bytes.IndexByte(tmpl, s1)
		if c < 0 {
			return errors.New("bad char")
		}
		for j := len(b) - 1; j >= 0; j-- {
			c += 58 * int(b[j])
			b[j] = byte(c % 256)
			c /= 256
		}
		if c > 0 {
			return errors.New("too long")
		}
	}
	return nil
}

// Version extracts the version byte from the byte slice.
func Version(b []byte) byte {
	return b[0]
}

// ComputeChecksum returns a four byte checksum computed from bytes (except for
// the last 4) of the slice.  The embedded checksum is not updated.
func ComputeChecksum(b []byte) (c [4]byte) {
	copy(c[:], doubleSHA256(b))
	return
}

// EmbeddedChecksum returns the checksum of the byte slice.
func EmbeddedChecksum(b []byte) (c [4]byte) {
	copy(c[:], b[len(b)-4:])
	return
}

// DoubleSHA256 computes a double sha256 hash of bytes (except for the last 4)
// of the slice.  This is the one function shared with the other bitcoin RC task.
// Returned is the full 32 byte sha256 hash.  (The checksum will be the first
// four bytes of the slice.)
func doubleSHA256(b []byte) []byte {
	h := sha256.New()
	h.Write(b[:len(b)-4])
	d := h.Sum([]byte{})
	h = sha256.New()
	h.Write(d)
	return h.Sum(d[:0])
}

// ExtractBitcoinAddress extracts any information related to bitcoin addresses from the current crawl.
func ExtractBitcoinAddress(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {
	bcaregex := regexp.MustCompile(`[13][a-km-zA-HJ-NP-Z1-9]{25,34}`)
	pkregex := regexp.MustCompile(`[LK][a-km-zA-HJ-NP-Z1-9]{51}`)
	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "text/html") {
			foundBCID := bcaregex.FindAllString(crawlRecord.Page.Snapshot, -1)
			for _, result := range foundBCID {
				if ValidateA58([]byte(result)) {
					anonreport.BitcoinAddresses = append(anonreport.BitcoinAddresses, result)
					osc.Database.InsertRelationship(osreport.HiddenService, "snapshot", "bitcoin-address", result)
				}
			}
			foundPKID := pkregex.FindAllString(crawlRecord.Page.Snapshot, -1)
			for _, result := range foundPKID {
				if ValidateP58([]byte(result)) {
					anonreport.BitcoinPrivateKeys = append(anonreport.BitcoinPrivateKeys, result)
					osc.Database.InsertRelationship(osreport.HiddenService, "snapshot", "bitcoin-private-key", result)
				}
			}
		}
	}
}
