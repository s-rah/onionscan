package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/s-rah/onionscan/utils"
)

const SEV_INFO = "info"
const SEV_LOW = "low"
const SEV_MEDIUM = "medium"
const SEV_HIGH = "high"
const SEV_CRITICAL = "critical"

type Risk struct {
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Fix         string   `json:"fix"`
	Items       []string `json:"items"`
}

type SimpleReport struct {
	HiddenService string `json:"hiddenService"`
	Risks         []Risk `json:"risks"`
}

func (osr *SimpleReport) AddRisk(severity string, title string, description string, fix string, items []string) {
	osr.Risks = append(osr.Risks, Risk{severity, title, description, fix, items})
}

// Serialize: Format as JSON
func (osr *SimpleReport) Serialize() (string, error) {
	report, err := json.Marshal(osr)
	if err != nil {
		return "", err
	}
	return string(report), nil
}

var risk_levels = map[string]string{
	SEV_INFO:     "\033[094mInfo:\033[0m",
	SEV_LOW:      "\033[093mLow Risk:\033[0m",
	SEV_MEDIUM:   "\033[093mMedium Risk:\033[0m",
	SEV_HIGH:     "\033[091mHigh Risk:\033[0m",
	SEV_CRITICAL: "\033[091mCritical Risk:\033[0m",
}

// Format as human-readable text to be printed to console
func (osr *SimpleReport) Format(width int) (string, error) {
	buffer := bytes.NewBuffer(nil)
	buffer.WriteString("--------------- OnionScan Report ---------------\n")

	buffer.WriteString(fmt.Sprintf("Generating Report for: %s\n\n", osr.HiddenService))
	const indent = "         "

	for _, risk := range osr.Risks {
		buffer.WriteString(risk_levels[risk.Severity] + " " + risk.Title + "\n")
		if len(risk.Description) > 0 {
			buffer.WriteString(indent + utils.FormatParagraphs(risk.Description, width, len(indent)) + "\n")
		}
		if len(risk.Fix) > 0 {
			buffer.WriteString(indent + utils.FormatParagraphs(risk.Fix, width, len(indent)) + "\n")
		}
		if len(risk.Items) > 0 {
			buffer.WriteString(indent + "Items Identified:\n")
			buffer.WriteString("\n")
			for _, item := range risk.Items {
				buffer.WriteString(indent + item + "\n")
			}
		}
		buffer.WriteString("\n")

	}
	if len(osr.Risks) == 0 {
		buffer.WriteString("No risks were found.\n")
	}
	return buffer.String(), nil
}

// Interface for SimpleReport checks
type SimpleReportCheck interface {
	Check(out *SimpleReport, report *AnonymityReport)
}

// EmailAddressCheck implementation
type EmailAddressCheck struct{}

func (srt *EmailAddressCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if len(report.EmailAddresses) > 0 {
		out.AddRisk(SEV_INFO, "Found Identities", "", "", report.EmailAddresses)
	}
}

// IPAddressCheck implementation
type IPAddressCheck struct{}

func (srt *IPAddressCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if len(report.IPAddresses) > 0 {
		out.AddRisk(SEV_INFO, "Found IP Addresses", "", "", report.IPAddresses)
	}
}

// AnalyticsIDsCheck implementation
type AnalyticsIDsCheck struct{}

func (srt *AnalyticsIDsCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if len(report.AnalyticsIDs) > 0 {
		out.AddRisk(SEV_INFO, "Found Analytics IDs", "", "", report.AnalyticsIDs)
	}
}

// BitcoinAddressesCheck implementation
type BitcoinAddressesCheck struct{}

func (srt *BitcoinAddressesCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if len(report.BitcoinAddresses) > 0 {
		out.AddRisk(SEV_INFO, "Found Bitcoin Addresses", "", "", report.BitcoinAddresses)
	}

}

// ApacheModStatusCheck implementation
type ApacheModStatusCheck struct{}

func (srt *ApacheModStatusCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if report.FoundApacheModStatus {
		out.AddRisk(SEV_HIGH, "Apache mod_status is enabled and accessible",
			"Why this is bad: An attacker can gain very valuable information from this internal status page including IP addresses, co-hosted services and user activity.",
			"To fix, disable mod_status or serve it on a different port than the configured hidden service.",
			nil)
	}
}

// RelatedClearnetDomainsCheck implementation
type RelatedClearnetDomainsCheck struct{}

func (srt *RelatedClearnetDomainsCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if len(report.RelatedClearnetDomains) > 0 {
		out.AddRisk(SEV_HIGH, "You are hosting a clearnet site on the same server as this onion service!",
			"Why this is bad: This may be intentional, but often isn't. Services are best operated in isolation such that a compromise of one does not mean a compromise of the other.",
			"To fix, host all services on separate infrastructure.",
			report.RelatedClearnetDomains)
	}
}

// RelatedOnionDomainsCheck implementation
type RelatedOnionServicesCheck struct{}

func (srt *RelatedOnionServicesCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if len(report.RelatedOnionServices) > 0 {
		out.AddRisk(SEV_MEDIUM, "You are hosting multiple onion services on the same server as this onion service!",
			"Why this is bad: This may be intentional, but often isn't. Hidden services are best operated in isolation such that a compromise of one does not mean a compromise of the other.",
			"To fix, host all services on separate infrastructure.",
			report.RelatedOnionServices)
	}
}

// OpenDirectoriesCheck implementation
type OpenDirectoriesCheck struct{}

func (srt *OpenDirectoriesCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if len(report.OpenDirectories) > 0 {
		var severity string
		var title string
		if len(report.OpenDirectories) > 10 {
			severity = SEV_MEDIUM
			title = "Large number of open directories were discovered!"
		} else {
			severity = SEV_LOW
			title = "Small number of open directories were discovered!"
		}

		out.AddRisk(severity, title,
			"Why this is bad: Open directories can reveal the existence of files not linked from the sites source code. Most of the time this is benign, but sometimes operators forget to clean up more sensitive folders.",
			"To fix, use .htaccess rules or equivalent to make reading directories listings forbidden. Quick Fix (Disable indexing globally) for Debian / Ubuntu running Apache: a2dismod autoindex as root.",
			report.OpenDirectories)
	}
}

// ExifImagesCheck implementation
type ExifImagesCheck struct{}

func (srt *ExifImagesCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if len(report.ExifImages) > 0 {
		var severity string
		var title string
		if len(report.OpenDirectories) > 10 {
			severity = SEV_HIGH
			title = "Large number of images with EXIF metadata were discovered!"
		} else {
			severity = SEV_MEDIUM
			title = "Small number of images with EXIF metadata were discovered!"
		}
		items := []string{}
		for _, image := range report.ExifImages {
			items = append(items, image.Location)
		}
		out.AddRisk(severity, title,
			"Why this is bad: EXIF metadata can itself deanonymize a user or service operator (e.g. GPS location, Name etc.). Or, when combined, can be used to link anonymous identities together.",
			"To fix, re-encode all images to strip EXIF and other metadata.",
			items)
	}
}

// PrivateKeyCheck implementation
type PrivateKeyCheck struct{}

func (srt *PrivateKeyCheck) Check(out *SimpleReport, report *AnonymityReport) {
	if report.PrivateKeyDetected {
		out.AddRisk(SEV_CRITICAL, "Hidden service private key is accessible!",
			"Why this is bad: This can be used to impersonate the service at any point in the future.",
			"To fix, generate a new hidden service and make sure the private_key file is not reachable from the web root.",
			nil)
	}
}

// Standard checks performed for SimpleReport generation
// Plugins can extend this list by calling RegisterSimpleReportCheck
var checks = []SimpleReportCheck{
	&EmailAddressCheck{},
	&IPAddressCheck{},
	&AnalyticsIDsCheck{},
	&BitcoinAddressesCheck{},
	&ApacheModStatusCheck{},
	&RelatedClearnetDomainsCheck{},
	&RelatedOnionServicesCheck{},
	&OpenDirectoriesCheck{},
	&ExifImagesCheck{},
	&PrivateKeyCheck{},
}

func SummarizeToSimpleReport(hiddenService string, report *AnonymityReport) *SimpleReport {
	var out = NewSimpleReport(hiddenService)
	for _, check := range checks {
		check.Check(out, report)
	}
	return out
}

func NewSimpleReport(hiddenService string) *SimpleReport {
	var osr = new(SimpleReport)
	osr.HiddenService = hiddenService
	return osr
}

func RegisterSimpleReportCheck(check SimpleReportCheck) {
	checks = append(checks, check)
}
