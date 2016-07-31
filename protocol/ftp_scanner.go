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

type FTPProtocolScanner struct {
}

func (sps *FTPProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionscanConfig, report *report.OnionScanReport) {
	// FTP
	osc.LogInfo(fmt.Sprintf("Checking %s FTP(21)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 21, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 21\n")
		report.FTPDetected = false
	} else {
		report.FTPDetected = true
		reader := bufio.NewReader(conn)
		banner, err := reader.ReadString('\n')
		if err == nil {
			report.FTPBanner = banner
			hash := sha1.Sum([]byte(banner))
			report.FTPFingerprint = hex.EncodeToString(hash[:])
			osc.LogInfo(fmt.Sprintf("Found FTP Banner: %s (%s)", banner, report.FTPFingerprint))
		}
	}
	if conn != nil {
		conn.Close()
	}
}
