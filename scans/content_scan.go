package scans

import (
	"github.com/s-rah/onionscan/report"
)

type ContentScan interface {
	ScanContent(content string, report *report.OnionScanReport)
}
