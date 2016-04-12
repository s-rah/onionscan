package protocol

import (
	"github.com/s-rah/onionscan/report"
)

type ProtocolScanner interface {
	ScanProtocol(hiddenService string, proxyAddress string, report *report.OnionScanReport)
}
