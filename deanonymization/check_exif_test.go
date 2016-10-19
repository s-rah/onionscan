package deanonymization

import (
	"github.com/s-rah/onionscan/report"
	"github.com/s-rah/onionscan/utils"
	"io/ioutil"
	"strings"
	"testing"
)

var truncatedJpeg = []byte{
	0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x02, 0x01, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x00, 0xff, 0xe1, 0x14, 0x0a, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x49, 0x49}

var expectedExif = map[string]string{
	"ColorSpace":              "65535",
	"ComponentsConfiguration": "\"\"",
	"DateTime":                "\"2012:11:04 05:42:02\"",
	"ExifIFDPointer":          "134",
	"ExifVersion":             "\"0210\"",
	"FlashpixVersion":         "\"0100\"",
	"Orientation":             "1",
	"PixelXDimension":         "0",
	"PixelYDimension":         "0",
	"ResolutionUnit":          "2",
	"XResolution":             "\"72/1\"",
	"YCbCrPositioning":        "1",
	"YResolution":             "\"72/1\"",
}

func TagsToMap(exiftags []report.ExifTag) map[string]string {
	rv := make(map[string]string)
	for _, tag := range exiftags {
		rv[tag.Name] = tag.Value
	}
	return rv
}

func CompareMaps(t *testing.T, foundTags map[string]string, expectedTags map[string]string) {
	var allTags []string
	for k := range expectedTags {
		allTags = append(allTags, k)
	}
	for k := range foundTags {
		allTags = append(allTags, k)
	}
	utils.RemoveDuplicates(&allTags)

	for _, tag := range allTags {
		val1, ok1 := foundTags[tag]
		val2, ok2 := expectedTags[tag]
		if ok1 != ok2 {
			if ok1 {
				t.Errorf("Mismatch: tag %s found but not expected", tag)
			} else {
				t.Errorf("Mismatch: tag %s expected but not found", tag)
			}
		} else if val1 != val2 {
			t.Errorf("Mismatch: tag %s found %s expected %s", tag, val1, val2)
		}
	}
}

func TestCheckExif(t *testing.T) {
	ctx := CreateEnvContext(t)
	defer ctx.Cleanup()

	// Test 1: no EXIF images
	CheckExif(ctx.osreport, ctx.report, ctx.osc)

	if len(ctx.report.ExifImages) > 0 {
		t.Errorf("Nothing crawled: Should not have detected EXIF")
	}

	// Test 2: corrupted JPEG image
	ctx.CreateBinaryPage("/test.jpg", 200, "image/jpeg", truncatedJpeg)

	CheckExif(ctx.osreport, ctx.report, ctx.osc)

	if len(ctx.report.ExifImages) > 0 {
		t.Errorf("Corrupt image: Should not have detected EXIF")
	}

	// Test 2: add real JPEG image
	data, err := ioutil.ReadFile("testdata/f1-exif.jpg")
	if err != nil {
		t.Errorf("Error reading test image")
	}
	ctx.CreateBinaryPage("/test2.jpg", 200, "image/jpeg", data)

	CheckExif(ctx.osreport, ctx.report, ctx.osc)

	if len(ctx.report.ExifImages) != 1 {
		t.Errorf("Should have detected EXIF in test image")
	}
	if !strings.HasSuffix(ctx.report.ExifImages[0].Location, "/test2.jpg") {
		t.Errorf("Location on EXIF image doesn't match expected")
	}
	var foundTags = TagsToMap(ctx.report.ExifImages[0].ExifTags)
	CompareMaps(t, foundTags, expectedExif)
}
