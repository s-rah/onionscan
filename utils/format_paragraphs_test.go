package utils

import (
	"testing"
)

type FormatParagraphsTest struct {
	input  string
	width  int
	indent int
	output string
}

var formatParagraphsTests = []FormatParagraphsTest{
	{"", 79, 0, ""},
	{"test", 79, 0, "test"},
	{" test", 79, 0, " test"},
	{"test test", 79, 0, "test test"},
	{"test test", 4, 0, "test\ntest"},
	{"testerde test", 4, 0, "testerde\ntest"},
	{"test test", 4, 4, "test\n    test"},
	// Make sure we don't indent a fully-new line following a too-long line ending
	{"test test\nabc", 4, 4, "test\n    test\nabc"},
	{"This_is_a_very_long_test_string_without_any_spaces_so_it_should_just_get_returned_as_is_despite_the_length until it gets here", 79, 0, "This_is_a_very_long_test_string_without_any_spaces_so_it_should_just_get_returned_as_is_despite_the_length\nuntil it gets here"},
	// Test wrap length is exact
	{"a b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p", 79, 0, "a b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de\nf g h i j k l m n o p"},
	{"x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p", 79, 0, "x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de\nf g h i j k l m n o p"},
	// Indent should be included in length of lines
	{"x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 a b c d e fg h i j k", 79, 4, "x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de\n    f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 a b c d e fg\n    h i j k"},
	{"This is a very long test string. This is a second sentence in the very long test string.", 79, 0, "This is a very long test string. This is a second sentence in the very long\ntest string."},
	{"This is a very long test string.\nThis is a second sentence in the very long test string. This is a third sentence in the very long test string.", 79, 0, "This is a very long test string.\nThis is a second sentence in the very long test string. This is a third\nsentence in the very long test string."},
	{"This is a very long test string.\n\nThis is a second sentence in the very long test string. This is a third sentence in the very long test string.", 79, 0, "This is a very long test string.\n\nThis is a second sentence in the very long test string. This is a third\nsentence in the very long test string."},
	{"Testing that normal newlines do not get indented.\nLike here.", 79, 0, "Testing that normal newlines do not get indented.\nLike here."},
}

func TestFormatParagraphs(t *testing.T) {
	for _, rec := range formatParagraphsTests {
		output := FormatParagraphs(rec.input, rec.width, rec.indent)
		if output != rec.output {
			t.Errorf("Format of \"%s\" (%d,%d) is \"%s\" instead of expected \"%s\"",
				rec.input, rec.width, rec.indent, output, rec.output)
		}
	}
}
