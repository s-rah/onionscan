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

type FTPProtocolScanner struct {
}

func (sps *FTPProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// FTP
	log.Printf("Checking %s FTP(21)\n", hiddenService)
	conn, err := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)("", hiddenService+":21")
	if err != nil {
		log.Printf("Failed to connect to service on port 21\n")
		report.FTPDetected = false
	} else {
		// TODO FTP Checking
		report.FTPDetected = true
		reader := bufio.NewReader(conn)
		banner, err := reader.ReadString('\n')
		if err == nil {
			report.FTPBanner = banner
			hash := sha1.Sum([]byte(banner))
			report.FTPFingerprint = hex.EncodeToString(hash[:])
			log.Printf("Found FTP Banner: %s (%s)", banner, report.FTPFingerprint)
		}
	}

}
