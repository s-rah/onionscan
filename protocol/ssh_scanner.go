package protocol

import (
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"golang.org/x/crypto/ssh"
	"h12.me/socks"
	"log"
	"net"
)

type SSHProtocolScanner struct {
}

func (sps *SSHProtocolScanner) ScanProtocol(hiddenService string, onionscanConfig *config.OnionscanConfig, report *report.OnionScanReport) {
	// SSH
	log.Printf("Checking %s ssh(22)\n", hiddenService)
	conn, err := socks.DialSocksProxy(socks.SOCKS5, onionscanConfig.TorProxyAddress)("", hiddenService+":22")
	if err != nil {
		log.Printf("Failed to connect to service on port 22\n")
		report.SSHDetected = false
	} else {
		// TODO SSH Checking
		report.SSHDetected = true

		config := &ssh.ClientConfig{
			HostKeyCallback: func(hostname string, addr net.Addr, key ssh.PublicKey) error {
				h := md5.New()
				h.Write(key.Marshal())

				fBytes := h.Sum(nil)
				fingerprint := string("")
				for i := 0; i < len(fBytes); i++ {
					if i+1 != len(fBytes) {
						fingerprint = fmt.Sprintf("%s%0.2x:", fingerprint, fBytes[i])
					} else {
						fingerprint = fmt.Sprintf("%s%0.2x", fingerprint, fBytes[i])
					}
				}
				report.SSHKey = fingerprint
				log.Printf("Found SSH Key %s\n", fingerprint)
				// We don't want to continue
				return errors.New("error")
			},
		}
		ssh.NewClientConn(conn, hiddenService+":22", config)

	}

}
