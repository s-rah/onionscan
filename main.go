package main

import (
	"flag"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		fmt.Printf("    onionscan [flags] hiddenservice\n")
		flag.PrintDefaults()
	}

	torProxyAddress := flag.String("torProxyAddress", "127.0.0.1:9050", "the address of the tor proxy to use")
	simpleReport := flag.Bool("simpleReport", true, "print out a simple report detailing what is wrong and how to fix it, true by default")
	reportFile := flag.String("reportFile", "", "the file destination path for report file")
	jsonReport := flag.Bool("jsonReport", false, "print out a json report providing a detailed report of the scan.")
	verbose := flag.Bool("verbose", false, "print out a verbose log output of the scan")
	directoryDepth := flag.Int("depth", 100, "depth of directory scan recursion (default: 100)")

	flag.Parse()

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	hiddenService := flag.Args()[0]

	log.Printf("Starting Scan of %s\n", hiddenService)
	log.Printf("This might take a few minutes..\n\n")

	if !*verbose {
		log.SetOutput(ioutil.Discard)
	}

	onionScan := new(OnionScan)
	onionScan.Config = config.Configure(*torProxyAddress, *directoryDepth)
	scanReport, err := onionScan.Scan(hiddenService)

	if err != nil {
		log.Fatalf("Error running scanner: %s", err)
	}

	if *jsonReport {
		report.GenerateJsonReport(*reportFile, scanReport)
	}

	if *simpleReport {
		report.GenerateSimpleReport(*reportFile, scanReport)
	}
}
