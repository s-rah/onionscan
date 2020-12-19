package utils

import (
	"golang.org/x/net/html"
	"strings"
	"testing"
)

func TestGetAttribute(t *testing.T) {
	z := html.NewTokenizer(strings.NewReader("<test a=\"b\" c=\"d\">"))
	z.Next()
	tok := z.Token()
	if GetAttribute(tok, "a") != "b" {
		t.Errorf("Attribute a should have value b")
	}
	if GetAttribute(tok, "b") != "" {
		t.Errorf("Attribute b is missing so should return empty value")
	}
}
