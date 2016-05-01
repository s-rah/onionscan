package protocol

import (
	"github.com/s-rah/onionscan/report"
)

type ProtocolScanner interface {
	ScanProtocol(hiddenService string, os *ProtocolConfig, report *report.OnionScanReport)
}
