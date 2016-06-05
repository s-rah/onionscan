package protocol

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
)

type SMTPProtocolScanner struct {
}

func (sps *SMTPProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// SMTP
	log.Printf("Checking %s SMTP(25)\n", hiddenService)
	conn, err := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)("", hiddenService+":25")
	if err != nil {
		log.Printf("Failed to connect to service on port 25\n")
		report.SMTPDetected = false
	} else {
		// TODO SMTP Checking
		report.SMTPDetected = true
		reader := bufio.NewReader(conn)
		banner, err := reader.ReadString('\n')
		if err == nil {
			report.SMTPBanner = banner
			hash := sha1.Sum([]byte(banner))
			report.SMTPFingerprint = hex.EncodeToString(hash[:])
			log.Printf("Found SMTP Banner: %s (%s)", banner, report.SMTPFingerprint)
		}
	}

}
