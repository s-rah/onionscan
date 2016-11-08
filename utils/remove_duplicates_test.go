package utils

import (
	"strings"
	"testing"
)

type RemoveDuplicatesTest struct {
	input  string
	output string
}

var RemoveDuplicatesTests = []RemoveDuplicatesTest{
	{"", ""},
	{"a,b,c,d", "a,b,c,d"},
	{"a,b,c,c", "a,b,c"},
	{"c,b,c,c", "c,b"},
	{"a,a,a,a", "a"},
}

func TestRemoveDuplicates(t *testing.T) {
	for _, rec := range RemoveDuplicatesTests {
		allTags := strings.Split(rec.input, ",")
		RemoveDuplicates(&allTags)
		output := strings.Join(allTags, ",")
		if output != rec.output {
			t.Errorf("RemoveDuplicates of \"%s\" is \"%s\" instead of expected \"%s\"",
				rec.input, output, rec.output)
		}
	}
}
