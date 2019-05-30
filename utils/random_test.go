package utils

import (
	"encoding/base64"
	"testing"
)

func TestGenerateRandomBytes(t *testing.T) {
	bytes, err := GenerateRandomBytes(10)
	if err != nil || len(bytes) != 10 {
		t.Errorf("Failed to get 10 random bytes")
	}
	bytes, err = GenerateRandomBytes(100)
	if err != nil || len(bytes) != 100 {
		t.Errorf("Failed to get 100 random bytes")
	}
	bytes, err = GenerateRandomBytes(0) // Should not fail
	if err != nil || len(bytes) != 0 {
		t.Errorf("Failed to get 0 random bytes")
	}
	bytes, err = GenerateRandomBytes(-1) // Should fail
	if err == nil {
		t.Errorf("Trying to get -1 random bytes should fail")
	}
}

func TestGenerateRandomString(t *testing.T) {
	s, err := GenerateRandomString(10)
	if err != nil {
		t.Errorf("Failed to get 10 random bytes")
	}
	var b []byte
	b, err = base64.URLEncoding.DecodeString(s)
	if err != nil || len(b) != 10 {
		t.Errorf("Did not get back 10 valid encoded bytes")
	}
}
