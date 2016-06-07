package config

import (
	"time"
)

type OnionscanConfig struct {
	TorProxyAddress string
	DirectoryDepth  int
	Fingerprint     bool
	Timeout         time.Duration
}

func Configure(torProxyAddress string, directoryDepth int, fingerprint bool, timeout int) *OnionscanConfig {
	onionScan := new(OnionscanConfig)
	onionScan.TorProxyAddress = torProxyAddress
	onionScan.DirectoryDepth = directoryDepth
	onionScan.Fingerprint = fingerprint
	onionScan.Timeout = time.Duration(time.Second * time.Duration(timeout))
	return onionScan
}
