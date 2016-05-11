package config

import ()

type OnionscanConfig struct {
	TorProxyAddress string
	DirectoryDepth  int
}

func Configure(torProxyAddress string, directoryDepth int) *OnionscanConfig {
	onionScan := new(OnionscanConfig)
	onionScan.TorProxyAddress = torProxyAddress
	onionScan.DirectoryDepth = directoryDepth
	return onionScan
}
