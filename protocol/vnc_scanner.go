package protocol

import (
	"fmt"
	"github.com/mitchellh/go-vnc"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
)

type VNCProtocolScanner struct {
}

type VNCInfo struct {
	DesktopName string
	Width       uint16
	Height      uint16
	Error       string
}

func (vncps *VNCProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionScanConfig, report *report.OnionScanReport) {
	// MongoDB
	osc.LogInfo(fmt.Sprintf("Checking %s VNC(5900)\n", hiddenService))
	conn, err := utils.GetNetworkConnection(hiddenService, 5900, osc.TorProxyAddress, osc.Timeout)
	if err != nil {
		osc.LogInfo("Failed to connect to service on port 5900\n")
		report.VNCDetected = false
	} else {
		osc.LogInfo("Detected possible VNC instance\n")

		report.VNCDetected = true
		config := new(vnc.ClientConfig)
		ms := make(chan vnc.ServerMessage)
		config.ServerMessageCh = ms
		vc, err := vnc.Client(conn, config)
		vncinfo := new(VNCInfo)
		if err == nil {
			osc.LogInfo(fmt.Sprintf("VNC Desktop Detected: %s %s (%v x %v)\n", hiddenService, vc.DesktopName, vc.FrameBufferWidth, vc.FrameBufferHeight))
			vncinfo.DesktopName = vc.DesktopName
			vncinfo.Width = vc.FrameBufferWidth
			vncinfo.Height = vc.FrameBufferHeight
		} else {
			osc.LogError(err)
			vncinfo.Error = err.Error()
		}
		report.AddProtocolInfo("vnc", 5900, vncinfo)

	}
	if conn != nil {
		conn.Close()
	}
}
