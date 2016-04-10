package scans

import (
	"github.com/s-rah/onionscan/report"
	"log"
	"regexp"
)

func StandardPageScan(scan Scanner, page string, status int, contents string, report *report.OnionScanReport) {
	log.Printf("Scanning %s%s\n", report.HiddenService, page)
	if status == 200 {
		log.Printf("\tPage %s%s is Accessible\n", report.HiddenService, page)

		log.Printf("\tScanning for Images\n")
		r := regexp.MustCompile("src=\"(" + "http://" + report.HiddenService + "/)?((.*?\\.jpg)|(.*?\\.png)|(.*?\\.jpeg)|(.*?\\.gif))\"")
		foundImages := r.FindAllStringSubmatch(string(contents), -1)
		for _, image := range foundImages {
			log.Printf("\t Found image %s\n", image[2])
			scan.ScanPage(report.HiddenService, "/"+image[2], report, CheckExif)
		}
	} else if status == 403 {
		log.Printf("\tPage %s%s is Forbidden\n", report.HiddenService, page)
	} else if status == 404 {
		log.Printf("\tPage %s%s is Does Not Exist\n", report.HiddenService, page)
	}
}
