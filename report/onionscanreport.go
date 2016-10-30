package report

import (
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"time"
)

type PGPKey struct {
	ArmoredKey  string `json:"armoredKey"`
	Identity    string `json:"identity"`
	FingerPrint string `json:"fingerprint"`
}

type BitcoinService struct {
	Detected        bool     `json:"detected"`
	UserAgent       string   `json:"userAgent"`
	ProtocolVersion int      `json:"prototocolVersion"`
	OnionPeers      []string `json:"onionPeers"`
}

type OnionScanReport struct {
	HiddenService  string    `json:"hiddenService"`
	DateScanned    time.Time `json:"dateScanned"`
	Online         bool      `json:"online"`
	PerformedScans []string  `json:"performedScans"`

	// Summary
	WebDetected      bool `json:"webDetected"`
	TLSDetected      bool `json:"tlsDetected"`
	SSHDetected      bool `json:"sshDetected"`
	RicochetDetected bool `json:"ricochetDetected"`
	RDPDetected      bool `json:"rdpDetected"`
	IRCDetected      bool `json:"ircDetected"`
	FTPDetected      bool `json:"ftpDetected"`
	SMTPDetected     bool `json:"smtpDetected"`
	BitcoinDetected  bool `json:"bitcoinDetected"`
	MongoDBDetected  bool `json:"mongodbDetected"`
	VNCDetected      bool `json:"vncDetected"`
	XMPPDetected     bool `json:"xmppDetected"`
	SkynetDetected   bool `json:"skynetDetected"`

	// Site Specific
	Crawls map[string]int `json:"crawls"`

	// Page Content
	PGPKeys []PGPKey `json:"pgpKeys"`

	// TLS
	Certificates []x509.Certificate `json:"certificates"`

	// Bitcoin
	BitcoinServices map[string]*BitcoinService `json:"bitcoinServices"`

	// SSH
	SSHKey    string `json:"sshKey"`
	SSHBanner string `json:"sshBanner"`

	// FTP
	FTPFingerprint string `json:"ftpFingerprint"`
	FTPBanner      string `json:"ftpBanner"`

	// SMTP
	SMTPFingerprint string `json:"smtpFingerprint"`
	SMTPBanner      string `json:"smtpBanner"`

	// Meta Info
	NextAction string `json:"lastAction"`
	TimedOut   bool   `json:"timedOut"`
	Error      error  `json:"error"`

	// Sub Reports
	AnonymityReport *AnonymityReport `json:"identifierReport"`
	SimpleReport    *SimpleReport    `json:"simpleReport"`
}

// LoadReportFromFile creates an OnionScan report from a json encoded file.
func LoadReportFromFile(filename string) (OnionScanReport, error) {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return OnionScanReport{}, err
	}
	res := OnionScanReport{}
	err = json.Unmarshal(dat, &res)
	return res, err
}

// NewOnionScanReport creates a new OnionScan report for the given hidden service.
func NewOnionScanReport(hiddenService string) *OnionScanReport {
	report := new(OnionScanReport)
	report.HiddenService = hiddenService
	report.DateScanned = time.Now()
	report.Crawls = make(map[string]int)
	report.PerformedScans = []string{}
	report.BitcoinServices = make(map[string]*BitcoinService)
	return report
}

// AddPGPKey adds a new PGP Key to the Report
func (osr *OnionScanReport) AddPGPKey(armoredKey, identity, fingerprint string) {
	osr.PGPKeys = append(osr.PGPKeys, PGPKey{armoredKey, identity, fingerprint})
	//TODO map of fingerprint:PGPKeys? and  utils.RemoveDuplicates(&osr.PGPKeys)
}

// AddBitcoinService adds a new Bitcoin Service to the Report
func (osr *OnionScanReport) AddBitcoinService(name string) *BitcoinService {
	var s = new(BitcoinService)
	osr.BitcoinServices[name] = s
	return s
}

// Serialize converts the report to a JSON representation
func (osr *OnionScanReport) Serialize() (string, error) {
	report, err := json.Marshal(osr)
	if err != nil {
		return "", err
	}
	return string(report), nil
}
