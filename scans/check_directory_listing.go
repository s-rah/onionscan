package scans

import (
	"github.com/s-rah/onionscan/report"
	"log"
	"regexp"
	"strings"
)

func CheckDirectoryListing(scan Scanner, dir string, status int, contents string, report *report.OnionScanReport) {
	if status == 200 && strings.Contains(string(contents), "Index of "+dir) {
		log.Printf("Detected Open Directory %s...\033[091mAlert!\033[0m\n", dir)

		report.AddOpenDirectory(dir)

		r := regexp.MustCompile(`href="((.*?\.jpg)|(.*?\.png)|(.*?\.jpeg)|(.*?\.gif))"`)
		foundImages := r.FindAllStringSubmatch(string(contents), -1)
		for _, image := range foundImages {
			log.Printf("\t Found image %s/%s\n", dir, image[1])
			scan.ScanPage(report.HiddenService, dir+"/"+image[1], report, CheckExif)
		}

		r = regexp.MustCompile(`href="((.*\.zip)|(.*\.tar)|(.*\.gz)|(.*\.pst)|(.*\.txt))"`)
		interestingFiles := r.FindAllStringSubmatch(string(contents), -1)
		for _, file := range interestingFiles {
			log.Printf("\t Found interesting file %s/%s\n", dir, file[1])
			//TODO: We can do further analysis here, for now, just report them.
			report.AddInterestingFile(dir+"/"+file[1])			
		}

		r = regexp.MustCompile(`href="([^/](.*?))/"`)
		subDir := r.FindAllStringSubmatch(string(contents), -1)
		for _, file := range subDir {
			log.Printf("\t Found subdir %s/%s\n", dir, file[1])
			//TODO: We can do further analysis here, for now, just report them.
			scan.ScanPage(report.HiddenService, dir+"/"+file[1], report, CheckDirectoryListing)		
		}

	} else {
		log.Printf("Directory %s either doesn't exist or is not readable\n", dir)
	}
}
