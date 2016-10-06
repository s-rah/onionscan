package utils

import (
	"bytes"
	"strings"
)

func FormatParagraphs(in string, width int, indent int) string {
	out := bytes.NewBuffer(nil)

	for il, para := range strings.Split(in, "\n") {
		rem_width := width
		if il == 0 { // Assume first line is indented by same amount by caller, subtract from available
			rem_width -= indent
		} else {
			out.WriteString("\n")
		}
		for iw, word := range strings.Split(para, " ") {
			if iw == 0 { // First word of a line - just place it
				out.WriteString(word)
				rem_width -= len(word)
			} else if (len(word) + 1) <= rem_width { // Second or latter - place for space and word
				out.WriteString(" " + word)
				rem_width -= len(word) + 1
			} else { // No place for this word on current line, skip to next line and place it
				out.WriteString("\n")
				rem_width = width
				for i := 0; i < indent; i++ {
					out.WriteString(" ")
					rem_width -= 1
				}
				out.WriteString(word)
				rem_width -= len(word)
			}
		}
	}
	return out.String()
}
