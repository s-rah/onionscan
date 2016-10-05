package report

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"
)

func GenerateJsonReport(reportFile string, report *AnonymityReport) {
	jsonOut, err := report.Serialize()

	if err != nil {
		log.Fatalf("Could not serialize json report %v", err)
	}

	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("%s\n", jsonOut))

	if len(reportFile) > 0 {
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
}

func GenerateSimpleReport(reportFile string, report *AnonymityReport, asJSON bool) {
	var report_str string
	var err error
	if asJSON {
		report_str, err = report.SimpleReport.Serialize()
	} else {
		report_str, err = report.SimpleReport.Format()
	}
	if err != nil {
		log.Printf("Could not generate report")
		return
	}

	if len(reportFile) > 0 {
		f, err := os.Create(reportFile)

		for err != nil {
			log.Printf("Cannot create report file: %s...trying again in 5 seconds...", err)
			time.Sleep(time.Second * 5)
			f, err = os.Create(reportFile)
		}

		defer f.Close()

		f.WriteString(report_str)
	} else {
		fmt.Print(report_str)
	}
}
