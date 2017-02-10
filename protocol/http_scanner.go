package protocol

import (
        "fmt"
        "github.com/s-rah/onionscan/config"
        "github.com/s-rah/onionscan/report"

        "github.com/s-rah/onionscan/spider"
        "github.com/s-rah/onionscan/utils"
        "net/http"
)

type HTTPProtocolScanner struct {
        Client *http.Client
}

func (hps *HTTPProtocolScanner) ScanProtocol(hiddenService string, osc *config.OnionScanConfig, report *report.OnionScanReport) {

        // HTTP
        ports := []int{80, 8080}

        for _, port := range ports {
                //fmt.Println(port)

                osc.LogInfo(fmt.Sprintf("Checking %s http(%d)\n", hiddenService, port))
                conn, err := utils.GetNetworkConnection(hiddenService, port, osc.TorProxyAddress, osc.Timeout)
                if conn != nil {
                        conn.Close()
                }

                if err != nil {
                        osc.LogInfo(fmt.Sprintf("Failed to connect to service on port %d\n", port))
                        report.WebDetected = false
                } else {
                        osc.LogInfo(fmt.Sprintf("Found potential service on http(%d)\n", port))
                        report.WebDetected = true
                        wps := new(spider.OnionSpider)
                        wps.Crawl(report.HiddenService, osc, report)
                }
        }
}
