package report

import (
	"encoding/json"
)

type ExifTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ExifImage struct {
	Location string    `json:"location"`
	ExifTags []ExifTag `json:"exifTags"`
}

// This is a summary report without all the crawl information
type AnonymityReport struct {
	PrivateKeyDetected bool `json:"privateKeyDetected"`

	// Apache Specific
	FoundApacheModStatus   bool     `json:"foundApacheModStatus"`
	ServerVersion          string   `json:"serverVersion"`
	RelatedOnionServices   []string `json:"relatedOnionServices"`
	RelatedClearnetDomains []string `json:"relatedOnionDomains"`
	IPAddresses            []string `json:"ipAddresses"`
	EmailAddresses         []string `json:"emailAddresses"`
	AnalyticsIDs           []string `json:"analyticsIDs"`
	BitcoinAddresses       []string `json:"bitcoinAddresses"`
	LinkedOnions           []string `json:"linkedOnions"`

	OpenDirectories []string    `json:"openDirectories"`
	ExifImages      []ExifImage `json:"exifImages"`
}

func (osr *AnonymityReport) AddExifImage(location string) {
	osr.ExifImages = append(osr.ExifImages, ExifImage{location, []ExifTag{}})
}

func (osr *AnonymityReport) AddExifTag(name string, value string) {
	osr.ExifImages[len(osr.ExifImages)-1].ExifTags = append(osr.ExifImages[len(osr.ExifImages)-1].ExifTags, ExifTag{name, value})
}

func (osr *AnonymityReport) AddRelatedOnionService(service string) {
	osr.RelatedOnionServices = append(osr.RelatedOnionServices, service)
}

func (osr *AnonymityReport) AddRelatedClearnetDomain(domain string) {
	osr.RelatedClearnetDomains = append(osr.RelatedClearnetDomains, domain)
}

func (osr *AnonymityReport) AddIPAddress(ip string) {
	osr.IPAddresses = append(osr.IPAddresses, ip)
}

func (osr *AnonymityReport) Serialize() (string, error) {
	report, err := json.Marshal(osr)
	if err != nil {
		return "", err
	}
	return string(report), nil
}
