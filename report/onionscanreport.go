package report

import (
	"encoding/json"
)

type ExifTag struct {
	Name string `json:"name"`
	Value string`json:"value"`
}

type ExifImage struct {
	Location string		`json:"location"`
	ExifTags	     []ExifTag `json:"exifTags"`	
}

type OnionScanReport struct {
	HiddenService        string   `json:"hiddenService"`
	ServerVersion        string   `json:"serverVersion"`
	FoundApacheModStatus bool     `json:"foundApacheModStatus"`
	RelatedOnionServices []string `json:"relatedOnionServices"`
	RelatedClearnetDomains []string `json:"relatedOnionDomains"`
	IP		     []string `json:"ipAddresses"`
	OpenDirectories      []string `json:"openDirectories"`	
	ExifImages	     []ExifImage `json:"exifImages"`
	InterestingFiles     []string `json:"interestingFiles"`
}

func NewOnionScanReport(hiddenService string) *OnionScanReport {
	return &OnionScanReport{HiddenService: hiddenService}
}

func (osr *OnionScanReport) AddOpenDirectory(dir string) {
	osr.OpenDirectories = append(osr.OpenDirectories, dir)
}

func (osr *OnionScanReport) AddRelatedOnionService(service string) {
	osr.RelatedOnionServices  = append(osr.RelatedOnionServices, service)
}

func (osr *OnionScanReport) AddRelatedClearnetDomain(domain string) {
	osr.RelatedClearnetDomains  = append(osr.RelatedClearnetDomains, domain)
}

func (osr *OnionScanReport) AddInterestingFile(file string) {
	osr.InterestingFiles  = append(osr.InterestingFiles, file)
}

func (osr *OnionScanReport) AddIPAddress(ip string) {
	osr.IP = append(osr.IP, ip)
}

func (osr *OnionScanReport) Serialize() (string, error) {
	report,err := json.Marshal(osr)
	if err != nil {
		return "", err
	}	
	return string(report), nil
}

func (osr *OnionScanReport) AddExifImage(location string) {
	osr.ExifImages = append(osr.ExifImages, ExifImage{location, []ExifTag{}})	
}

func (osr *OnionScanReport) AddExifTag(name string, value string) {
	osr.ExifImages[len(osr.ExifImages)-1].ExifTags = append(osr.ExifImages[len(osr.ExifImages)-1].ExifTags , ExifTag{name, value})	
}
