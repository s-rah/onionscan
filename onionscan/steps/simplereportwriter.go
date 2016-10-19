package steps

import (
	"fmt"
	"github.com/s-rah/onionscan/report"
	"log"
	"os"
	"time"
)

// SimpleReportWriter is a PipelineStep which outputs a human friendly summary
// of an OnionScanReport.
type SimpleReportWriter struct {
	reportFile string
	asJSON     bool
	width      int
}

// Init sets up a SimpleReportWriter.
func (srw *SimpleReportWriter) Init(outputFile string, asJSON bool, width int) {
	srw.reportFile = outputFile
	srw.asJSON = asJSON
	srw.width = width
}

// Do runs the PipelineStep for SimpleReportWriter to output the formatted report.
func (srw *SimpleReportWriter) Do(r *report.OnionScanReport) error {
	var reportStr string
	var err error
	if srw.asJSON {
		reportStr, err = r.SimpleReport.Serialize()
	} else {
		reportStr, err = r.SimpleReport.Format(srw.width)
	}
	if err != nil {
		return err
	}

	if len(srw.reportFile) > 0 {
		reportFile := r.HiddenService + "." + srw.reportFile
		f, err := os.Create(reportFile)

		for err != nil {
			log.Printf("Cannot create report file: %s...trying again in 5 seconds...", err)
			time.Sleep(time.Second * 5)
			f, err = os.Create(reportFile)
		}

		defer f.Close()

		f.WriteString(reportStr)
	} else {
		fmt.Print(reportStr)
	}
	return nil
}
