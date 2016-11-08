package utils

import (
	"testing"
)

type WithoutSubDomainsTest struct {
	input  string
	output string
}

var WithoutSubDomainsTests = []WithoutSubDomainsTest{
	{"", ""},
	{"com", ""},
	{"test.com", "test.com"},
	{"test.test.com", "test.com"},
	{"test.test.test.com", "test.com"},
}

func TestWithoutSubdomains(t *testing.T) {
	for _, rec := range WithoutSubDomainsTests {
		output := WithoutSubdomains(rec.input)
		if output != rec.output {
			t.Errorf("WithoutSubdomains of \"%s\" is \"%s\" instead of expected \"%s\"",
				rec.input, output, rec.output)
		}
	}
}

type WithoutProtocolTest struct {
	input  string
	output string
}

var WithoutProtocolTests = []WithoutProtocolTest{
	{"", ""},
	{"notactuallyan.onion", "notactuallyan.onion"},
	{"https://notactuallyan.onion", "notactuallyan.onion"},
	{"http://notactuallyan.onion", "notactuallyan.onion"},
	{"//notactuallyan.onion", "notactuallyan.onion"},
}

func TestWithoutProtocol(t *testing.T) {
	for _, rec := range WithoutProtocolTests {
		output := WithoutProtocol(rec.input)
		if output != rec.output {
			t.Errorf("WithoutProtocol of \"%s\" is \"%s\" instead of expected \"%s\"",
				rec.input, output, rec.output)
		}
	}
}
