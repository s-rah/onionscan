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

type OnionScanReport struct {
	HiddenService string    `json:"hiddenService"`
	DateScanned   time.Time `json:"dateScanned"`
	Online        bool      `json:"online"`

	// Summary
	WebDetected      bool `json:"webDetected"`
	TLSDetected      bool `json:"tlsDetected"`
	SSHDetected      bool `json:"sshDetected"`
	RicochetDetected bool `json:"ricochetDetected"`
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

	//Bitcoin
	BitcoinAddresses []string `json:"bitcoinAddresses"`
	BitcoinUserAgent string `json:"bitcoinUserAgent"`
	BitcoinProtocolVersion int `json:"bitcoinPrototocolVersion"`

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
	report.DateScanned = time.Now()
	report.Crawls = make(map[string]int)
	return report
}

func (osr *OnionScanReport) AddPGPKey(armoredKey, identity, fingerprint string) {
	osr.PGPKeys = append(osr.PGPKeys, PGPKey{armoredKey, identity, fingerprint})
	//TODO map of fingerprint:PGPKeys? and  utils.RemoveDuplicates(&osr.PGPKeys)
}

func (osr *OnionScanReport) Serialize() (string, error) {
	report, err := json.Marshal(osr)
	if err != nil {
		return "", err
	}
	return string(report), nil
}
