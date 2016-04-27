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

	if _, ok := report.ResponseHeaders["X-Frame-Options"]; !ok {
		lowRisk += 1
	}

	if _, ok := report.ResponseHeaders["X-XSS-Protection"]; !ok {
		lowRisk += 1
	}

	if _, ok := report.ResponseHeaders["X-Content-Type-Options"]; !ok {
		lowRisk += 1
	}

	if _, ok := report.ResponseHeaders["Content-Security-Policy"]; !ok {
		lowRisk += 1
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

	if report.ResponseHeaders != nil {
		if _, ok := report.ResponseHeaders["X-Frame-Options"]; !ok {
			buffer.WriteString("\033[091mLow Risk:\033[0m missing X-Frame-Options HTTP header discovered!\n")
			buffer.WriteString("\t Why this is bad: Provides Clickjacking protection. Values: deny - no rendering within a frame, sameorigin - no rendering if origin mismatch, allow-from: DOMAIN - allow rendering if framed by frame loaded from DOMAIN\n")
			buffer.WriteString("\t To fix, use X-Frame-Options: deny\n")
		}
		if _, ok := report.ResponseHeaders["X-XSS-Protection"]; !ok {
			buffer.WriteString("\033[091mLow Risk:\033[0m missing X-XSS-Protection HTTP header discovered!\n")
			buffer.WriteString("\t Why this is bad: his header enables the Cross-site scripting (XSS) filter built into most recent web browsers. It's usually enabled by default anyway, so the role of this header is to re-enable the filter for this particular website if it was disabled by the user. This header is supported in IE 8+, and in Chrome (not sure which versions). The anti-XSS filter was added in Chrome 4. Its unknown if that version honored this header.\n")
			buffer.WriteString("\t To fix, use X-XSS-Protection: 1; mode=block\n")
		}
		if _, ok := report.ResponseHeaders["X-Content-Type-Options"]; !ok {
			buffer.WriteString("\033[091mLow Risk:\033[0m missing X-Content-Type-Options HTTP header discovered!\n")
			buffer.WriteString("\t Why this is bad: The only defined value, \"nosniff\", prevents Internet Explorer and Google Chrome from MIME-sniffing a response away from the declared content-type. This also applies to Google Chrome, when downloading extensions. This reduces exposure to drive-by download attacks and sites serving user uploaded content that, by clever naming, could be treated by MSIE as executable or dynamic HTML files.\n")
			buffer.WriteString("\t To fix, use  X-Content-Type-Options: nosniff\n")
		}
		if _, ok := report.ResponseHeaders["Content-Security-Policy"]; !ok {
			buffer.WriteString("\033[091mLow Risk:\033[0m missing X-Content-Type-Options HTTP header discovered!\n")
			buffer.WriteString("\t Why this is bad: Content Security Policy requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browser renders pages (e.g., inline JavaScript disabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks, including Cross-site scripting and other cross-site injections.\n")
			buffer.WriteString("\t To fix, use  Content-Security-Policy: default-src 'self'\n")
		}

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


