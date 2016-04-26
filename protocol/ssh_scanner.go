package protocol

import (
	"github.com/s-rah/onionscan/report"
	"h12.me/socks"
	"log"
	"golang.org/x/crypto/ssh"
	"net"
	"errors"
	"crypto/md5"
	"fmt"
)

type SSHProtocolScanner struct {

}

func (sps *SSHProtocolScanner) ScanProtocol(hiddenService string, proxyAddress string, report *report.OnionScanReport) {
	// SSH
	log.Printf("Checking %s ssh(22)\n", hiddenService)
	conn, err := socks.DialSocksProxy(socks.SOCKS5, proxyAddress)("", hiddenService+":22")
	if err != nil {
		log.Printf("Failed to connect to service on port 22\n")
	} else {
		// TODO SSH Checking
		report.SSHDetected = true
	
		config := &ssh.ClientConfig {
			HostKeyCallback : func (hostname string, addr net.Addr, key ssh.PublicKey) error {
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
		ssh.NewClientConn(conn,hiddenService+":22",config)

	}

}
