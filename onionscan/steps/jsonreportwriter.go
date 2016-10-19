package steps

import (
	"bytes"
	"fmt"
	"github.com/s-rah/onionscan/report"
	"log"
	"os"
	"time"
)

// JSONReportWriter is a sink Pipeline step used to output a JSON formated
// version of the OnionScan report.
type JSONReportWriter struct {
	reportFile string
}

// Init sets up a JsonReportWriter
func (jrw *JSONReportWriter) Init(outputFile string) {
	jrw.reportFile = outputFile
}

// Do runs the PipelineStep for JsonReportWriter to output the formatted report.
func (jrw *JSONReportWriter) Do(r *report.OnionScanReport) error {
	jsonOut, err := r.Serialize()

	if err != nil {
		return err
	}

	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("%s\n", jsonOut))

	if len(jrw.reportFile) > 0 {
		reportFile := r.HiddenService + "." + jrw.reportFile
		f, err := os.Create(reportFile)

		for err != nil {
			log.Printf("Cannot create report file: %s...trying again in 5 seconds...", err)
			time.Sleep(time.Second * 5)
			f, err = os.Create(reportFile)
		}

		defer f.Close()

		f.WriteString(buffer.String())
	} else {
		fmt.Print(buffer.String())
	}
	return nil
}
