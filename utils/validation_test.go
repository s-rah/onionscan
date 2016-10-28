package utils

import (
	"testing"
)

func TestIsOnion(t *testing.T) {

	test := IsOnion("maschqwtr4lqt2pj.onion")
	if !test {
		t.Errorf("%s should have matched!", "maschqwtr4lqt2pj.onion")
	}

	test = IsOnion("subdomain.lots.of.maschqwtr4lqt2pj.onion")
	if !test {
		t.Errorf("%s should have matched!", "subdomain.lots.of.maschqwtr4lqt2pj.onion")
	}

	test = IsOnion("thisis9notavalidonion.onion")
	if test {
		t.Errorf("%s should not have matched!", "thisis9notavalidonion.onion")
	}

	test = IsOnion("maschqwtr4lqt2pj.com")
	if test {
		t.Errorf("%s should not have matched!", "maschqwtr4lqt2pj.com")
	}

	test = IsOnion("www.thisisnotanonionitistoolong.onion")
	if test {
		t.Errorf("%s should not have matched!", "www.thisisnotanonionitistoolong.onion")
	}

}
