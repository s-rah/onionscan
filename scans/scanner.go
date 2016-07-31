package scans

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
)

type Scanner interface {
	ScanPage(string, string, *report.OnionScanReport, *config.OnionscanConfig, func(Scanner, string, int, string, *report.OnionScanReport, *config.OnionscanConfig))
	ScrapePage(string, string) (error, []byte, int)
}
