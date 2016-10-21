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
	RDPDetected	 bool `json:"rdpDetected"`
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

	// Bitcoin
	BitcoinAddresses []string                   `json:"bitcoinAddresses"`
	BitcoinServices  map[string]*BitcoinService `json:"bitcoinServices"`

	// SSH
	SSHKey    string `json:"sshKey"`
	SSHBanner string `json:"sshBanner"`

	// FTP
	FTPFingerprint string `json:"ftpFingerprint"`
	FTPBanner      string `json:"ftpBanner"`

	// SMTP
	SMTPFingerprint string `json:"smtpFingerprint"`
	SMTPBanner      string `json:"smtpBanner"`

	ProtocolInfoList []ProtocolInfo `json::"protocolInfoList"`

	NextAction string `json:"lastAction"`
	TimedOut   bool   `json:"timedOut"`
}

type ProtocolInfo struct {
	Type string      `json:"type"`
	Port uint        `json:"port:`
	Info interface{} `json:"info"`
}

func (osr *OnionScanReport) AddProtocolInfo(protocolType string, protocolPort uint, protocolInfo interface{}) {
	osr.ProtocolInfoList = append(osr.ProtocolInfoList, ProtocolInfo{protocolType, protocolPort, protocolInfo})
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
	report.PerformedScans = []string{}
	report.BitcoinServices = make(map[string]*BitcoinService)
	return report
}

func (osr *OnionScanReport) AddPGPKey(armoredKey, identity, fingerprint string) {
	osr.PGPKeys = append(osr.PGPKeys, PGPKey{armoredKey, identity, fingerprint})
	//TODO map of fingerprint:PGPKeys? and  utils.RemoveDuplicates(&osr.PGPKeys)
}

func (osr *OnionScanReport) AddBitcoinService(name string) *BitcoinService {
	var s = new(BitcoinService)
	osr.BitcoinServices[name] = s
	return s
}

func (osr *OnionScanReport) Serialize() (string, error) {
	report, err := json.Marshal(osr)
	if err != nil {
		return "", err
	}
	return string(report), nil
}
