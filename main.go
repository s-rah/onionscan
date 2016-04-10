package main

import (
	"flag"
	"fmt"
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
	jsonReport := flag.Bool("jsonReport", false, "print out a json report providing a detailed report of the scan.")
	verbose := flag.Bool("verbose", false, "print out a verbose log output of the scan")

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

	onionScan := Configure(*torProxyAddress)
	report, err := onionScan.Scan(hiddenService)

	if err != nil {
		log.Fatalf("Error running scanner: %s", err)
	}

	if *jsonReport {
		jsonOut, _ := report.Serialize()
		fmt.Printf("%s\n", jsonOut)
	}

	// FIXME: This needs refactoring, would be nice to put these into an external config files
	if *simpleReport {

		highRisk := 0
		mediumRisk := 0
		lowRisk := 0

		if report.FoundApacheModStatus {
			highRisk += 1
		}

		if len(report.RelatedClearnetDomains) > 0 {
			highRisk += 1
		}

		if len(report.RelatedOnionServices) > 0 {
			mediumRisk += 1
		}

		if report.ExifImages != nil {
			if len(report.ExifImages) > 10 {
				highRisk += 1
			} else {
				mediumRisk += 1
			}
		}

		if report.OpenDirectories != nil {
			if len(report.OpenDirectories) > 3 {
				mediumRisk += 1
			} else {
				lowRisk += 1
			}
		}

		if report.InterestingFiles != nil {
			if len(report.InterestingFiles) > 10 {
				mediumRisk += 1
			} else {
				lowRisk += 1
			}
		}

		fmt.Printf("--------------- OnionScan Report ---------------\n")
		fmt.Printf("High Risk Issues: %d\n", highRisk)
		fmt.Printf("Medium Risk Issues: %d\n", mediumRisk)
		fmt.Printf("Low Risk Issues: %d\n", lowRisk)
		fmt.Printf("\n")

		if report.FoundApacheModStatus {
			fmt.Printf("\033[091mHigh Risk:\033[0m Apache mod_status is enabled and accessible\n")
			fmt.Printf("\t Why this is bad: An attacker can gain very valuable information\n\t from this internal status page including IP addresses, co-hosted services and user activity.\n")
			fmt.Printf("\t To fix, disable mod_status or serve it on a different port than the configured hidden service\n\n")
		}

		if len(report.RelatedClearnetDomains) > 0 {
			fmt.Printf("\033[091mHigh Risk:\033[0m You are hosting a clearnet site on the same server as this onion service!\n")
			fmt.Printf("\t Why this is bad: This may be intentional, but often isn't.\n\t Services are best operated in isolation such that a compromise of one does not mean a compromise of the other.\n")
			fmt.Printf("\t To fix, host all services on separate infrastructure\n\n")
		}

		if len(report.RelatedOnionServices) > 0 {
			fmt.Printf("\033[091mMedium Risk:\033[0m You are hosting multiple onion services on the same server as this onion service!\n")
			fmt.Printf("\t Why this is bad: This may be intentional, but often isn't.\n\t Hidden services are best operated in isolation such that a compromise of one does not mean a compromise of the other.\n")
			fmt.Printf("\t To fix, host all services on separate infrastructure\n\n")
		}

		if len(report.ExifImages) > 0 {
			if len(report.ExifImages) > 10 {
				fmt.Printf("\033[091mHigh Risk:\033[0m Large number of images with EXIF metadata were discovered!\n")
			} else {
				fmt.Printf("\033[091mMedium Risk:\033[0m Small number of images with EXIF metadata were discovered!\n")
			}

			fmt.Printf("\t Why this is bad: EXIF metadata can itself deanonymize a user or\n\t service operator (e.g. GPS location, Name etc.). Or, when combined, can be used to link anonymous identities together.\n")
			fmt.Printf("\t To fix, re-encode all images to strip EXIF and other metadata.\n")
			fmt.Printf("\t Images Identified:\n")
			for _, image := range report.ExifImages {
				fmt.Printf("\t\t%s\n", image.Location)
			}
			fmt.Printf("\n")
		}

		if len(report.OpenDirectories) > 0 {
			if len(report.OpenDirectories) > 10 {
				fmt.Printf("\033[091mMedium Risk:\033[0m Large number of open directories were discovered!\n")
			} else {
				fmt.Printf("\033[091mLow Risk:\033[0m Small number of open directories were discovered!\n")
			}

			fmt.Printf("\t Why this is bad: Open directories can reveal the existence of files\n\t not linked from the sites source code. Most of the time this is benign, but sometimes operators forget to clean up more sensitive folders.\n")
			fmt.Printf("\t To fix, use .htaccess rules or equivalent to make reading directories listings forbidden.\n")
			fmt.Printf("\t Directories Identified:\n")
			for _, dir := range report.OpenDirectories {
				fmt.Printf("\t\t%s\n", dir)
			}
			fmt.Printf("\n")
		}

	}
}
