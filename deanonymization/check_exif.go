package deanonymization

import (
	"bytes"
	"github.com/rwcarlsen/goexif/exif"
	"github.com/rwcarlsen/goexif/tiff"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"net/url"
	"strings"
)

// ExifWalker captures functionality to process all exif data obtained from an image.
type ExifWalker struct {
	anonreport *report.AnonymityReport
}

// Walk takes the given exif information and stores it the the anonymity report.
func (w *ExifWalker) Walk(name exif.FieldName, val *tiff.Tag) error {
	w.anonreport.AddExifTag(string(name), val.String())
	return nil
}

// CheckExif extracts all EXIF metadata out of any images processed during the current crawl.
func CheckExif(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {
	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)

		if crawlRecord.Page.Status == 200 && strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "image/jpeg") {
			exifdata, err := exif.Decode(bytes.NewReader(crawlRecord.Page.Raw))

			if err != nil {
				// We don't care if we fail - try next image
				continue
			}

			uri, _ := url.Parse(crawlRecord.URL)
			anonreport.AddExifImage(uri.Path)
			exifdata.Walk(&ExifWalker{anonreport})
		}
	}
}
