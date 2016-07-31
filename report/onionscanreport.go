package report

import (
	"crypto/x509"
	"encoding/json"
	"github.com/s-rah/onionscan/utils"
	"io/ioutil"
	"time"
)

type ExifTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ExifImage struct {
	Location string    `json:"location"`
	ExifTags []ExifTag `json:"exifTags"`
}

type PGPKey struct {
	ArmoredKey  string `json:"armoredKey"`
	Identity    string `json:"identity"`
	FingerPrint string `json:"fingerprint"`
}

type OnionScanReport struct {
	HiddenService string    `json:"hiddenService"`
	DateScanned   time.Time `json:"dateScanned"`

	// Summary
	WebDetected        bool `json:"webDetected"`
	TLSDetected        bool `json:"tlsDetected"`
	SSHDetected        bool `json:"sshDetected"`
	RicochetDetected   bool `json:"ricochetDetected"`
	IRCDetected        bool `json:"ircDetected"`
	FTPDetected        bool `json:"ftpDetected"`
	SMTPDetected       bool `json:"smtpDetected"`
	BitcoinDetected    bool `json:"bitcoinDetected"`
	MongoDBDetected    bool `json:"mongodbDetected"`
	VNCDetected        bool `json:"vncDetected"`
	XMPPDetected       bool `json:"xmppDetected"`
	SkynetDetected     bool `json:"skynetDetected"`
	PrivateKeyDetected bool `json:"privateKeyDetected"`

	// Web Specific
	ServerPoweredBy           string            `json:"serverPoweredBy"`
	ServerVersion             string            `json:"serverVersion"`
	FoundApacheModStatus      bool              `json:"foundApacheModStatus"`
	RelatedOnionServices      []string          `json:"relatedOnionServices"`
	RelatedClearnetDomains    []string          `json:"relatedOnionDomains"`
	LinkedSites               []string          `json:"linkedSites"`
	InternalPages             []string          `json:"internalPages"`
	IP                        []string          `json:"ipAddresses"`
	OpenDirectories           []string          `json:"openDirectories"`
	ExifImages                []ExifImage       `json:"exifImages"`
	InterestingFiles          []string          `json:"interestingFiles"`
	PageReferencedDirectories []string          `json:"pageReferencedDirectories"`
	PGPKeys                   []PGPKey          `json:"pgpKeys"`
	Hashes                    []string          `json:"hashes"`
	Snapshot                  string            `json:"snapshot"`
	PageTitle                 string            `json:"pageTitle"`
	ResponseHeaders           map[string]string `json:"responseHeaders"`

	// TLS
	Certificates []x509.Certificate `json:"certificates"`

	//Bitcoin
	BitcoinAddresses []string `json:"bitcoinAddresses"`

	// SSH
	SSHKey    string `json:"sshKey"`
	SSHBanner string `json:"sshBanner"`

	// FTP
	FTPFingerprint string `json:"ftpFingerprint"`
	FTPBanner      string `json:"ftpBanner"`

	// SMTP
	SMTPFingerprint string `json:"smtpFingerprint"`
	SMTPBanner      string `json:"smtpBanner"`

	NextAction string `json:"lastAction"`
	TimedOut   bool
}

func LoadReportFromFile(filename string) (OnionScanReport, error) {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return OnionScanReport{}, err
	}
	res := OnionScanReport{}
	err = json.Unmarshal(dat, &res)
	return res, err
}

func NewOnionScanReport(hiddenService string) *OnionScanReport {
	report := new(OnionScanReport)
	report.HiddenService = hiddenService
	report.ResponseHeaders = make(map[string]string)
	report.DateScanned = time.Now()
	return report
}

func (osr *OnionScanReport) AddOpenDirectory(dir string) {
	osr.OpenDirectories = append(osr.OpenDirectories, dir)
}

func (osr *OnionScanReport) AddRelatedOnionService(service string) {
	osr.RelatedOnionServices = append(osr.RelatedOnionServices, service)
}

func (osr *OnionScanReport) AddRelatedClearnetDomain(domain string) {
	osr.RelatedClearnetDomains = append(osr.RelatedClearnetDomains, domain)
}

func (osr *OnionScanReport) AddInterestingFile(file string) {
	osr.InterestingFiles = append(osr.InterestingFiles, file)
}

func (osr *OnionScanReport) AddIPAddress(ip string) {
	osr.IP = append(osr.IP, ip)
}

func (osr *OnionScanReport) AddLinkedSite(site string) {
	osr.LinkedSites = append(osr.LinkedSites, site)
	utils.RemoveDuplicates(&osr.LinkedSites)
}

func (osr *OnionScanReport) AddInternalPage(site string) {
	osr.InternalPages = append(osr.InternalPages, site)
	utils.RemoveDuplicates(&osr.InternalPages)
}

func (osr *OnionScanReport) AddPGPKey(armoredKey, identity, fingerprint string) {
	osr.PGPKeys = append(osr.PGPKeys, PGPKey{armoredKey, identity, fingerprint})
	//TODO map of fingerprint:PGPKeys? and  utils.RemoveDuplicates(&osr.PGPKeys)
}

func (osr *OnionScanReport) AddResponseHeader(name string, value string) {
	osr.ResponseHeaders[name] = value
}

func (osr *OnionScanReport) Serialize() (string, error) {
	report, err := json.Marshal(osr)
	if err != nil {
		return "", err
	}
	return string(report), nil
}

func (osr *OnionScanReport) AddExifImage(location string) {
	osr.ExifImages = append(osr.ExifImages, ExifImage{location, []ExifTag{}})
}

func (osr *OnionScanReport) AddExifTag(name string, value string) {
	osr.ExifImages[len(osr.ExifImages)-1].ExifTags = append(osr.ExifImages[len(osr.ExifImages)-1].ExifTags, ExifTag{name, value})
}

func (osr *OnionScanReport) AddPageReferencedDirectory(directory string) {
	osr.PageReferencedDirectories = append(osr.PageReferencedDirectories, directory)
}
