package config

type OnionscanConfig struct {
	TorProxyAddress string
	DirectoryDepth  int
	Fingerprint     bool
}

func Configure(torProxyAddress string, directoryDepth int, fingerprint bool) *OnionscanConfig {
	onionScan := new(OnionscanConfig)
	onionScan.TorProxyAddress = torProxyAddress
	onionScan.DirectoryDepth = directoryDepth
	onionScan.Fingerprint = fingerprint
	return onionScan
}
