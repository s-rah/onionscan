package config

import (
	"log"
	"time"
)

type OnionscanConfig struct {
	TorProxyAddress string
	DirectoryDepth  int
	Fingerprint     bool
	Timeout         time.Duration
	Verbose         bool
}

func Configure(torProxyAddress string, directoryDepth int, fingerprint bool, timeout int, verbose bool) *OnionscanConfig {
	onionScan := new(OnionscanConfig)
	onionScan.TorProxyAddress = torProxyAddress
	onionScan.DirectoryDepth = directoryDepth
	onionScan.Fingerprint = fingerprint
	onionScan.Timeout = time.Duration(time.Second * time.Duration(timeout))
	onionScan.Verbose = verbose
	return onionScan
}

func (os *OnionscanConfig) LogInfo(message string) {
	if os.Verbose {
		log.Printf("INFO: %v", message)
	}
}

func (os *OnionscanConfig) LogError(err error) {
	log.Printf("ERROR: %v", err)
}
