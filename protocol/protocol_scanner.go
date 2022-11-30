package protocol

import (
	"github.com/csimsv/onionscan/config"
	"github.com/csimsv/onionscan/report"
)

type Scanner interface {
	ScanProtocol(hiddenService string, onionscanConfig *config.OnionScanConfig, report *report.OnionScanReport)
}
