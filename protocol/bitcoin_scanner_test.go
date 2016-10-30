package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type ChecksumTest struct {
	input  []byte
	output string
}

var checksumTests = []ChecksumTest{
	{[]byte{}, "5df6e0e2"},
	{[]byte{0x00}, "1406e058"},
}

func TestChecksum(t *testing.T) {
	for _, rec := range checksumTests {
		checksum := hex.EncodeToString(Checksum(rec.input))
		if checksum != rec.output {
			t.Errorf("Checksum of %s is %s instead of %s",
				rec.input, checksum, rec.output)
		}
	}
}

type CompactSizeTest struct {
	input    []byte
	val      uint64
	sizesize int
}

var compactSizeTests = []CompactSizeTest{
	{[]byte{}, 0, 0},
	{[]byte{0xff}, 0, 0},
	{[]byte{0x00}, 0x00, 1},
	{[]byte{0x12}, 0x12, 1},
	{[]byte{0xfc}, 0xfc, 1},
	{[]byte{0xfd, 0x12, 0x34}, 0x3412, 3},
	{[]byte{0xfe, 0x12, 0x34, 0x56, 0x78}, 0x78563412, 5},
	{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0xffffffffffffffff, 9},
	{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}, 0xffffffffffffffff, 9},
}

func TestReadCompactSize(t *testing.T) {
	for _, rec := range compactSizeTests {
		val, sizesize := ReadCompactSize(rec.input)
		if sizesize != rec.sizesize || val != rec.val {
			t.Errorf("ReadCompactSize of %s is (0x%x,%d) instead of (0x%x,%d)",
				hex.EncodeToString(rec.input), val, sizesize, rec.val, rec.sizesize)
		}
	}
}

type CStringTest struct {
	input  []byte
	output string
}

var cstringTests = []CStringTest{
	{[]byte{}, ""},
	{[]byte{0x00, 0x00, 0x00, 0x01}, ""},
	{[]byte{0x6e, 0x75, 0x6c, 0x00}, "nul"},
	{[]byte{0x6e, 0x75, 0x6c, 0x6c}, "null"},
}

func TestCstring(t *testing.T) {
	for _, rec := range cstringTests {
		val := cstring(rec.input)
		if val != rec.output {
			t.Errorf("cstring of %s is %s instead of %s",
				hex.EncodeToString(rec.input), val, rec.output)
		}
	}
}

type EncodeOnionTest struct {
	ipv6      []byte
	onion     string
	encode    bool
	encode_ok bool
	decode    bool
	decode_ok bool
}

var encodeOnionTests = []EncodeOnionTest{
	{[]byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43, 0x6b, 0x65, 0xc8, 0xf7, 0x97, 0xda, 0xca, 0x18, 0xaa, 0x1d}, "nns4r54x3lfbrkq5.onion", true, true, true, true},
	{[]byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43, 0x6b, 0x65, 0xc8, 0xf7, 0x97, 0xda, 0xca, 0x18, 0xaa, 0x1d}, "test.nns4r54x3lfbrkq5.onion", true, true, false, false},
	{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "aaaanns4r54x3lfbrkq5.onion", true, false, false, false},
	{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "", true, false, true, false},
	{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "invalid.onion", true, false, true, false},
	{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "google.com", true, false, true, false},
	{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40}, "", true, false, true, false},
	{[]byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "aaaaaaaaaaaaaaaa.onion", true, true, true, true},
}

func TestEncodeOnion(t *testing.T) {
	for _, rec := range encodeOnionTests {
		if rec.encode {
			val, err := EncodeOnion(rec.onion)
			if (err == nil) != rec.encode_ok {
				t.Errorf("EncodeOnion error was %s instead of %v", err, rec.decode_ok)
			}
			if rec.encode_ok && !bytes.Equal(val, rec.ipv6) {
				t.Errorf("EncodeOnion of %s is %s instead of %s",
					rec.onion, hex.EncodeToString(val), hex.EncodeToString(rec.ipv6))
			}
		}
	}
}

func TestDecodeOnion(t *testing.T) {
	for _, rec := range encodeOnionTests {
		if rec.decode {
			val, err := DecodeOnion(rec.ipv6)
			if (err == nil) != rec.decode_ok {
				t.Errorf("DecodeOnion error was %s instead of %v", err, rec.decode_ok)
			}
			if rec.decode_ok && val != rec.onion {
				t.Errorf("DecodeOnion of %s is %s instead of %s",
					hex.EncodeToString(rec.ipv6), val, rec.onion)
			}
		}
	}
}
