package scans

import (
	"github.com/s-rah/onionscan/report"
	"github.com/xiam/exif"
	"io"	
	"log"
	"strings"
)

func CheckExif(scan Scanner, page string, status int, contents string, report *report.OnionScanReport) {
	if status == 200 {
		reader := exif.New()
		_, err := io.Copy(reader, strings.NewReader(contents))

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
			report.AddExifImage(page)

			for name, val := range reader.Tags {
				log.Printf("\t \033[091mAlert!\033[0m Found Exif Tag%s: %s\n", name, val)
				report.AddExifTag(name, val)
			}
		}
	}
}
