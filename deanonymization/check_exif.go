package deanonymization

import (
	"bytes"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/report"
	"github.com/xiam/exif"
	"io"
	"net/url"
	"strings"
)

func CheckExif(osreport *report.OnionScanReport, anonreport *report.AnonymityReport, osc *config.OnionScanConfig) {

	for _, id := range osreport.Crawls {
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)

		if crawlRecord.Page.Status == 200 && strings.Contains(crawlRecord.Page.Headers.Get("Content-Type"), "image/jpeg") {
			reader := exif.New()
			_, err := io.Copy(reader, bytes.NewReader(crawlRecord.Page.Raw))

			// exif.FoundExifInData is a signal that the EXIF parser has all it needs,
			// it doesn't need to be given the whole image.
			if err != nil && err != exif.ErrFoundExifInData {
				// We don't care if we fail
				return
			}

			err = reader.Parse()

			if err != nil {
				// We don't care if we fail
				return
			}

			if len(reader.Tags) > 0 {
				uri, _ := url.Parse(crawlRecord.URL)
				anonreport.AddExifImage(uri.Path)

				for name, val := range reader.Tags {
					anonreport.AddExifTag(name, val)
				}
			}
		}
	}
}
