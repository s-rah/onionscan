package report

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"
)

func GenerateJsonReport(reportFile string, report *AnonymityReport) {
	jsonOut, err := report.Serialize()

	if err != nil {
		log.Fatalf("Could not serialize json report %v", err)
	}

	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("%s\n", jsonOut))

	if len(reportFile) > 0 {
		f, err := os.Create(reportFile)

		for err != nil {
			log.Printf("Cannot create report file: %s...trying again in 5 seconds...", err)
			time.Sleep(time.Second * 5)
			f, err = os.Create(reportFile)
		}

		defer f.Close()

		f.WriteString(buffer.String())
	} else {
		fmt.Print(buffer.String())
	}
}

func GenerateSimpleReport(reportFile string, report *AnonymityReport) {

	buffer := bytes.NewBuffer(nil)
	buffer.WriteString("--------------- OnionScan Report ---------------\n")

	buffer.WriteString(fmt.Sprintf("Generating Report for: %s\n\n", report.OnionScanReport.HiddenService))

	if len(report.EmailAddresses) > 0 {
		buffer.WriteString("Found Identities:\n")
		for _, email := range report.EmailAddresses {
			buffer.WriteString(fmt.Sprintf("\t %s\n", email))
		}
		buffer.WriteString("\n")
	}

	if len(report.IPAddresses) > 0 {
		buffer.WriteString("Found IP Addresses:\n")
		for _, ip := range report.IPAddresses {
			buffer.WriteString(fmt.Sprintf("\t %s\n", ip))
		}
		buffer.WriteString("\n")
	}

	if len(report.RelatedClearnetDomains) > 0 {
		buffer.WriteString("Found Co-hosted Clearnet Domains:\n")
		for _, domain := range report.RelatedClearnetDomains {
			buffer.WriteString(fmt.Sprintf("\t %s\n", domain))
		}
		buffer.WriteString("\n")
	}

	if len(report.RelatedOnionServices) > 0 {
		buffer.WriteString("Found Co-hosted Onion Domains:\n")
		for _, domain := range report.RelatedOnionServices {
			buffer.WriteString(fmt.Sprintf("\t %s\n", domain))
		}
		buffer.WriteString("\n")
	}

	if len(report.AnalyticsIDs) > 0 {
		buffer.WriteString("Found Analytics IDs:\n")
		for _, id := range report.AnalyticsIDs {
			buffer.WriteString(fmt.Sprintf("\t %s\n", id))
		}
		buffer.WriteString("\n")
	}

	if len(report.BitcoinAddresses) > 0 {
		buffer.WriteString("Found Bitcoin Addresses:\n")
		for _, id := range report.BitcoinAddresses {
			buffer.WriteString(fmt.Sprintf("\t %s\n", id))
		}
		buffer.WriteString("\n")
	}

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

	if len(report.OpenDirectories) > 0 {
		if len(report.OpenDirectories) > 10 {
			buffer.WriteString("\033[091mMedium Risk:\033[0m Large number of open directories were discovered!\n")
		} else {
			buffer.WriteString("\033[091mLow Risk:\033[0m Small number of open directories were discovered!\n")
		}

		buffer.WriteString("\t Why this is bad: Open directories can reveal the existence of files\n\t not linked from the sites source code. Most of the time this is benign, but sometimes operators forget to clean up more sensitive folders.\n")
		buffer.WriteString("\t To fix, use .htaccess rules or equivalent to make reading directories listings forbidden.\n")
		buffer.WriteString("\t Quick Fix (Disable indexing globally) for Debian / Ubuntu running Apache: a2dismod autoindex as root.\n")
		buffer.WriteString("\t Directories Identified:\n")
		for _, dir := range report.OpenDirectories {
			buffer.WriteString(fmt.Sprintf("\t\t%s\n", dir))
		}
		buffer.WriteString("\n")
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

	if len(reportFile) > 0 {
		f, err := os.Create(reportFile)

		for err != nil {
			log.Printf("Cannot create report file: %s...trying again in 5 seconds...", err)
			time.Sleep(time.Second * 5)
			f, err = os.Create(reportFile)
		}

		defer f.Close()

		f.WriteString(buffer.String())
	} else {
		fmt.Print(buffer.String())
	}
}
