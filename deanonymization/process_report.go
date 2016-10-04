package deanonymization

import (
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

func ProcessReport(osreport *report.OnionScanReport, osc *config.OnionScanConfig) *report.AnonymityReport {
	anonreport := new(report.AnonymityReport)
	ApacheModStatus(osreport, anonreport, osc)
	CheckExposedDirectories(osreport, anonreport, osc)
	PGPContentScan(osreport, anonreport, osc)
	MailtoScan(osreport, anonreport, osc)
	CheckExif(osreport, anonreport, osc)
	PrivateKey(osreport, anonreport, osc)
	ExtractGoogleAnalyticsID(osreport, anonreport, osc)
	ExtractGooglePublisherID(osreport, anonreport, osc)
	ExtractBitcoinAddress(osreport, anonreport, osc)
	utils.RemoveDuplicates(&anonreport.RelatedOnionServices)
	utils.RemoveDuplicates(&anonreport.RelatedClearnetDomains)
	utils.RemoveDuplicates(&anonreport.IPAddresses)
	utils.RemoveDuplicates(&anonreport.EmailAddresses)
	utils.RemoveDuplicates(&anonreport.AnalyticsIDs)
	utils.RemoveDuplicates(&anonreport.BitcoinAddresses)
	anonreport.OnionScanReport = osreport
	return anonreport
}
