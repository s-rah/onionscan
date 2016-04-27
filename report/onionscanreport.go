package report

import (
	"encoding/json"
	"github.com/s-rah/onionscan/utils"
	"io/ioutil"
)

type ExifTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ExifImage struct {
	Location string    `json:"location"`
	ExifTags []ExifTag `json:"exifTags"`
}

type OnionScanReport struct {
	WebDetected      bool `json:"webDetected"`
	SSHDetected      bool `json:"sshDetected"`
	RicochetDetected bool `json:"ricochetDetected"`
	IRCDetected      bool `json:"ircDetected"`
	FTPDetected      bool `json:"ftpDetected"`
	SMTPDetected     bool `json:"smtpDetected"`

	BitcoinDetected bool `json:"bitcoinDetected"`

	HiddenService             string      `json:"hiddenService"`
	ServerPoweredBy           string      `json:"serverPoweredBy"`
	ServerVersion             string      `json:"serverVersion"`
	FoundApacheModStatus      bool        `json:"foundApacheModStatus"`
	RelatedOnionServices      []string    `json:"relatedOnionServices"`
	RelatedClearnetDomains    []string    `json:"relatedOnionDomains"`
	LinkedSites               []string    `json:"linkedSites"`
	IP                        []string    `json:"ipAddresses"`
	OpenDirectories           []string    `json:"openDirectories"`
	ExifImages                []ExifImage `json:"exifImages"`
	InterestingFiles          []string    `json:"interestingFiles"`
	PageReferencedDirectories []string    `json:"pageReferencedDirectories"`

	Hashes          []string `json:"hashes"`
	SSHKey          string   `json:"sshKey"`
	Snapshot        string   `json:"snapshot"`
	PageTitle       string   `json:"pageTitle"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
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
	return &OnionScanReport{HiddenService: hiddenService, ResponseHeaders: make(map[string]string)}
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
