package protocol

import (
	"crypto/tls"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

type TLSProtocolScanner struct {
}

func (sps *TLSProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionscanConfig, report *report.OnionScanReport) {
	osc.LogInfo(fmt.Sprintf("Checking %s TLS(443)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 443, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 443\n")
		report.TLSDetected = false
	} else {
		osc.LogInfo("Found TLS Endpoint\n")
		report.TLSDetected = true
		config := &tls.Config{
			InsecureSkipVerify: true,
		}
		tlsConn := tls.Client(conn, config)
		tlsConn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		for _, certificate := range tlsConn.ConnectionState().PeerCertificates {
			osc.LogInfo(fmt.Sprintf("Found Certificate %v \n", certificate))
			report.Certificates = append(report.Certificates, *certificate)
		}
		tlsConn.Close()
	}
	if conn != nil {
		conn.Close()
	}
}
