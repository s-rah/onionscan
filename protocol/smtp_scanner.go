package protocol

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

type SMTPProtocolScanner struct {
}

func (sps *SMTPProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionscanConfig, report *report.OnionScanReport) {
	// SMTP
	osc.LogInfo(fmt.Sprintf("Checking %s SMTP(25)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 25, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 25\n")
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
			osc.LogInfo(fmt.Sprintf("Found SMTP Banner: %s (%s)", banner, report.SMTPFingerprint))
		}
	}
	if conn != nil {
		conn.Close()
	}
}
