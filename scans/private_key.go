package scans

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
)

func PrivateKeyScan(scan Scanner, page string, status int, contents string, report *report.OnionScanReport, osc *config.OnionscanConfig) {
	osc.LogInfo(fmt.Sprintf("Scanning %s\n", page))
	if status == 200 {
		osc.LogInfo(fmt.Sprintf("\tPrivate Key %s is Accessible!!\n", page))
		report.PrivateKeyDetected = true
	}
}
