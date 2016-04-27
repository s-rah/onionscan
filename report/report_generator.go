package report

import (
	"fmt"
	"os"
	"bytes"
	"log"
)

func GenerateJsonReport(reportFile string, report *OnionScanReport) {
	jsonOut, _ := report.Serialize()
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("%s\n", jsonOut))

	if len(reportFile) > 0 {
		f, err := os.Create(reportFile)
		if err != nil {
			log.Fatalf("Cannot create report file: %s", err)
			panic(err)
		}

		defer f.Close()

		f.WriteString(buffer.String())
	} else {
		fmt.Print(buffer.String())
	}
}

func GenerateSimpleReport(reportFile string, report *OnionScanReport) {
	highRisk := 0
	mediumRisk := 0
	lowRisk := 0

	if report.FoundApacheModStatus {
		highRisk += 1
	}

	if len(report.RelatedClearnetDomains) > 0 {
		highRisk += 1
	}

	if len(report.RelatedOnionServices) > 0 {
		mediumRisk += 1
	}

	if report.ExifImages != nil {
		if len(report.ExifImages) > 10 {
			highRisk += 1
		} else {
			mediumRisk += 1
		}
	}

	if report.OpenDirectories != nil {
		if len(report.OpenDirectories) > 3 {
			mediumRisk += 1
		} else {
			lowRisk += 1
		}
	}

	if report.InterestingFiles != nil {
		if len(report.InterestingFiles) > 10 {
			mediumRisk += 1
		} else {
			lowRisk += 1
		}
	}

	var buffer bytes.Buffer

	buffer.WriteString("--------------- OnionScan Report ---------------\n")
	buffer.WriteString(fmt.Sprintf("High Risk Issues: %d\n", highRisk))
	buffer.WriteString(fmt.Sprintf("Medium Risk Issues: %d\n", mediumRisk))
	buffer.WriteString(fmt.Sprintf("Low Risk Issues: %d\n", lowRisk))
	buffer.WriteString("\n")

	if report.FoundApacheModStatus {
		buffer.WriteString("\033[091mHigh Risk:\033[0m Apache mod_status is enabled and accessible\n")
		buffer.WriteString("\t Why this is bad: An attacker can gain very valuable information\n\t from this internal status page including IP addresses, co-hosted services and user activity.\n")
		buffer.WriteString("\t To fix, disable mod_status or serve it on a different port than the configured hidden service\n\n")
	}

	if len(report.RelatedClearnetDomains) > 0 {
		buffer.WriteString("\033[091mHigh Risk:\033[0m You are hosting a clearnet site on the same server as this onion service!\n")
		buffer.WriteString("\t Why this is bad: This may be intentional, but often isn't.\n\t Services are best operated in isolation such that a compromise of one does not mean a compromise of the other.\n")
		buffer.WriteString("\t To fix, host all services on separate infrastructure\n\n")
	}

	if len(report.RelatedOnionServices) > 0 {
		buffer.WriteString("\033[091mMedium Risk:\033[0m You are hosting multiple onion services on the same server as this onion service!\n")
		buffer.WriteString("\t Why this is bad: This may be intentional, but often isn't.\n\t Hidden services are best operated in isolation such that a compromise of one does not mean a compromise of the other.\n")
		buffer.WriteString("\t To fix, host all services on separate infrastructure\n\n")
	}

	if len(report.ExifImages) > 0 {
		if len(report.ExifImages) > 10 {
			buffer.WriteString("\033[091mHigh Risk:\033[0m Large number of images with EXIF metadata were discovered!\n")
		} else {
			buffer.WriteString("\033[091mMedium Risk:\033[0m Small number of images with EXIF metadata were discovered!\n")
		}

		buffer.WriteString("\t Why this is bad: EXIF metadata can itself deanonymize a user or\n\t service operator (e.g. GPS location, Name etc.). Or, when combined, can be used to link anonymous identities together.\n")
		buffer.WriteString("\t To fix, re-encode all images to strip EXIF and other metadata.\n")
		buffer.WriteString("\t Images Identified:\n")
		for _, image := range report.ExifImages {
			buffer.WriteString(fmt.Sprintf("\t\t%s\n", image.Location))
		}
		buffer.WriteString("\n")
	}

	if len(report.OpenDirectories) > 0 {
		if len(report.OpenDirectories) > 10 {
			buffer.WriteString("\033[091mMedium Risk:\033[0m Large number of open directories were discovered!\n")
		} else {
			buffer.WriteString("\033[091mLow Risk:\033[0m Small number of open directories were discovered!\n")
		}

		buffer.WriteString("\t Why this is bad: Open directories can reveal the existence of files\n\t not linked from the sites source code. Most of the time this is benign, but sometimes operators forget to clean up more sensitive folders.\n")
		buffer.WriteString("\t To fix, use .htaccess rules or equivalent to make reading directories listings forbidden.\n")
		buffer.WriteString("\t Directories Identified:\n")
		for _, dir := range report.OpenDirectories {
			buffer.WriteString(fmt.Sprintf("\t\t%s\n", dir))
		}
		buffer.WriteString("\n")
	}


	if len(reportFile) > 0 {
		f, err := os.Create(reportFile)
		if err != nil {
			log.Fatalf("Cannot create report file: %s", err)
			panic(err)
		}

		defer f.Close()

		f.WriteString(buffer.String())
	} else {
		fmt.Print(buffer.String())
	}
}


