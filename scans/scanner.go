package scans

import (
	"github.com/s-rah/onionscan/report"
)

type Scanner interface {
	ScanPage(string, string, *report.OnionScanReport, func(Scanner, string, int, string, *report.OnionScanReport))
	ScrapePage(string, string) (error, []byte, int)
}
