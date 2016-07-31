package scans

import (
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"regexp"
	"strings"
)

func CheckDirectoryListing(depth int) func(Scanner, string, int, string, *report.OnionScanReport, *config.OnionscanConfig) {
	return func(scan Scanner, dir string, status int, contents string, report *report.OnionScanReport, osc *config.OnionscanConfig) {
		CheckDirectoryListingDepth(scan, dir, status, depth, contents, report, osc)
	}
}

func CheckDirectoryListingDepth(scan Scanner, dir string, status int, depth int, contents string, report *report.OnionScanReport, osc *config.OnionscanConfig) {
	if status == 200 && strings.Contains(string(contents), "Index of "+dir) {
		osc.LogInfo(fmt.Sprintf("Detected Open Directory %s...\033[091mAlert!\033[0m\n", dir))

		report.AddOpenDirectory(dir)

		r := regexp.MustCompile(`href="((.*?\.jpg)|(.*?\.png)|(.*?\.jpeg)|(.*?\.gif))"`)
		foundImages := r.FindAllStringSubmatch(string(contents), -1)
		for _, image := range foundImages {
			osc.LogInfo(fmt.Sprintf("\t Found image %s/%s\n", dir, image[1]))
			scan.ScanPage(report.HiddenService, dir+"/"+image[1], report, osc, CheckExif)
		}

		r = regexp.MustCompile(`href="((.*\.zip)|(.*\.tar)|(.*\.gz)|(.*\.pst)|(.*\.txt))"`)
		interestingFiles := r.FindAllStringSubmatch(string(contents), -1)
		for _, file := range interestingFiles {
			osc.LogInfo(fmt.Sprintf("\t Found interesting file %s/%s\n", dir, file[1]))
			//TODO: We can do further analysis here, for now, just report them.
			report.AddInterestingFile(dir + "/" + file[1])
		}

		r = regexp.MustCompile(`href="([^/](.*?))/"`)
		subDir := r.FindAllStringSubmatch(string(contents), -1)
		for _, file := range subDir {
			osc.LogInfo(fmt.Sprintf("\t Found subdir %s/%s\n", dir, file[1]))
			//TODO: We can do further analysis here, for now, just report them.
			if depth > 0 {
				scan.ScanPage(report.HiddenService, dir+"/"+file[1], report, osc, CheckDirectoryListing(depth-1))
			}
		}

	} else {
		osc.LogInfo(fmt.Sprintf("Directory %s either doesn't exist or is not readable\n", dir))
	}
}
