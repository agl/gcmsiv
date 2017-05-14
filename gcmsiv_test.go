package gcmsiv

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestToFromBytes(t *testing.T) {
	a := fieldElement([4]uint64{0x3b2c8aefd44be966, 0x2e2b34ca59fa4c88, 0, 0})

	aBytes := a.Bytes()
	if result := fieldElementFromBytes(aBytes[:]); result != a {
		t.Errorf("Converting to/from bytes does not round-trip: got %s, want %s", result, a)
	}
}

func TestWrap(t *testing.T) {
	plaintext := make([]byte, 16*2)
	key := make([]byte, 32)
	nonce, _ := hex.DecodeString("000000000000000000000000")
	const ss = "x^123 + x^119 + x^118 + x^117 + x^112 + x^111 + x^108 + x^107 + x^101 + x^100 + x^99 + x^97 + x^95 + x^94 + x^87 + x^86 + x^84 + x^83 + x^82 + x^78 + x^77 + x^76 + x^74 + x^73 + x^70 + x^69 + x^68 + x^67 + x^66 + x^62 + x^59 + x^56 + x^55 + x^54 + x^53 + x^50 + x^49 + x^45 + x^44 + x^43 + x^42 + x^41 + x^38 + x^37 + x^36 + x^35 + x^32 + x^31 + x^30 + x^28 + x^27 + x^26 + x^21 + x^17 + x^16 + x^15 + x^13 + x^12 + x^11 + x^8 + x^6 + x^3 + x^2 + 1"
	ssBytes := fieldElementFromSage("x", ss).Bytes()
	copy(plaintext[16:], ssBytes[:])

	gcmsiv, err := NewGCMSIV(key)
	if err != nil {
		t.Fatal(err)
	}

	verbose = true
	gcmsiv.Seal(nil, nonce, plaintext, nil)
}

func TestWrapPartialBlock(t *testing.T) {
	plaintext := make([]byte, 16+8)
	key := make([]byte, 32)
	nonce, _ := hex.DecodeString("000000000000000000000000")
	const ss = "x^126 + x^123 + x^122 + x^117 + x^116 + x^115 + x^114 + x^113 + x^109 + x^107 + x^106 + x^104 + x^103 + x^102 + x^100 + x^94 + x^89 + x^87 + x^85 + x^82 + x^80 + x^79 + x^78 + x^74 + x^73 + x^72 + x^65 + x^64 + x^60 + x^57 + x^56 + x^55 + x^54 + x^53 + x^52 + x^51 + x^50 + x^48 + x^46 + x^45 + x^44 + x^43 + x^42 + x^41 + x^40 + x^38 + x^37 + x^36 + x^35 + x^34 + x^29 + x^26 + x^25 + x^24 + x^22 + x^13 + x^12 + x^10 + x^9 + x^7 + x^6 + x^5 + x^3 + x + 1"

	ssBytes := fieldElementFromSage("x", ss).Bytes()
	copy(plaintext, ssBytes[:])

	gcmsiv, err := NewGCMSIV(key)
	if err != nil {
		t.Fatal(err)
	}

	verbose = true
	gcmsiv.Seal(nil, nonce, plaintext, nil)
}

func TestFieldOps(t *testing.T) {
	a := fieldElement([4]uint64{0x3b2c8aefd44be966, 0x2e2b34ca59fa4c88, 0, 0})
	b := fieldElement([4]uint64{0xff, 0, 0, 0})

	addResult := a.add(b).String()
	if expected := "2e2b34ca59fa4c883b2c8aefd44be999"; expected != addResult {
		t.Errorf("a+b = %s, but expected %s", addResult, expected)
	}

	mulResult := a.mul(b).String()
	if expected := "e90aaa71616dbc6ef29ddce975618537"; expected != mulResult {
		t.Errorf("a⊗b = %s, but expected %s", mulResult, expected)
	}

	dotResult := a.dot(b).String()
	if expected := "94c340816b42d63aea917e1e4063e5eb"; expected != dotResult {
		t.Errorf("a•b = %s, but expected %s", dotResult, expected)
	}
}

func TestPolyval(t *testing.T) {
	var hBytes [16]byte
	hBytes[0] = 3

	input := make([]byte, 32)
	input[0] = 1
	input[16] = 0x40

	polyvalResult := fmt.Sprintf("%x", polyval(hBytes, input))
	if expected := "95000000000000000000000000283bfd"; expected != polyvalResult {
		t.Errorf("polyval(h, input) = %s, but expected %s", polyvalResult, expected)
	}
}

func TestHelloWorld(t *testing.T) {
	plaintext := []byte("Hello world")
	ad := []byte("example")
	key, _ := hex.DecodeString("ee8e1ed9ff2540ae8f2ba9f50bc2f27c")
	nonce, _ := hex.DecodeString("752abad3e0afb5f434dc4310")

	gcmsiv, err := NewGCMSIV(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := gcmsiv.Seal(nil, nonce, plaintext, ad)
	const expected = "5d349ead175ef6b1def6fd4fbcdeb7e4793f4a1d7e4faa70100af1"
	if hexCiphertext := hex.EncodeToString(ciphertext); hexCiphertext != expected {
		t.Errorf("got %s, wanted %s", hexCiphertext, expected)
	}
}

func TestAgainstVectors128(t *testing.T) {
	in, err := os.Open("output_add_info_be128.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	processTestVectors(t, doTest, in)
}

func TestAgainstVectors256(t *testing.T) {
	in, err := os.Open("output_add_info_be256.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	processTestVectors(t, doTest, in)
}

func doTest(t *testing.T, testNum int, values map[string][]byte) {
	key, foundKey := values["K1"]
	if !foundKey {
		t.Fatalf("#%d: no key %#v", testNum, values)
	}

	gcmsiv, err := NewGCMSIV(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := values["NONCE"][:12]
	msg := values["MSG"]
	ad := values["AAD"]

	verbose = true
	ciphertext := gcmsiv.Seal(nil, nonce, msg, ad)
	verbose = false
	tag := ciphertext[len(ciphertext)-16:]
	ct := ciphertext[:len(ciphertext)-16]

	if expectedTag := values["TAG"]; !bytes.Equal(tag, expectedTag) {
		t.Errorf("#%d: got tag %x, but expected %x", testNum, tag, expectedTag)
	}

	if expectedCiphertext := values["CIPHERTEXT"]; !bytes.Equal(ct, expectedCiphertext) {
		t.Errorf("#%d: got ciphertext %x, but expected %x", testNum, ciphertext, expectedCiphertext)
	}

	plaintext, err := gcmsiv.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		t.Errorf("#%d: failed to Open ciphertext: %s", testNum, err)
	} else if !bytes.Equal(plaintext, msg) {
		t.Errorf("#%d: Open returned %x, but should be %x", testNum, plaintext, msg)
	}
}

func processTestVectors(t *testing.T, doTest func(t *testing.T, testNum int, values map[string][]byte), in io.Reader) {
	var values map[string][]byte
	var lastKey string
	var testNum int

	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 {
			lastKey = ""
			continue
		}

		if strings.HasPrefix(line, "*****") {
			lastKey = ""
			if values != nil && len(values) > 0 {
				doTest(t, testNum, values)
			}

			testNum++
			values = make(map[string][]byte)
			continue
		}

		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(lastKey) == 0 {
				continue
			}

			line = strings.TrimSpace(line)
			bytes, err := hex.DecodeString(line)
			if err == nil {
				values[lastKey] = append(values[lastKey], bytes...)
			}

			continue
		}

		if i := strings.LastIndexByte(line, '='); i >= 0 {
			key := strings.TrimSpace(line[:i])
			if j := strings.IndexByte(key, '='); j >= 0 {
				key = strings.TrimSpace(key[:j])
			}

			value := strings.TrimSpace(line[i+1:])
			bytes, err := hex.DecodeString(value)
			if err == nil {
				lastKey = key
				values[key] = bytes
			}

			continue
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if values != nil {
		doTest(t, testNum, values)
	}
}

func disabledTestExtraVectors(t *testing.T) {
	r := sha3.NewShake128()
	r.Write([]byte("AES-GCM-SIV"))

	const keyLen = 32
	for l := 0; l < 1024/16; l++ {
		key := make([]byte, keyLen)
		r.Read(key)
		nonce := make([]byte, 12)
		r.Read(nonce)
		msg := make([]byte, l*16+l%16)
		r.Read(msg)
		ad := make([]byte, l*8+l%8)
		r.Read(ad)

		gcmsiv, _ := NewGCMSIV(key)
		ciphertext := gcmsiv.Seal(nil, nonce, msg, ad)
		tag := ciphertext[len(ciphertext)-16:]
		ct := ciphertext[:len(ciphertext)-16]

		fmt.Printf("\nKEY: %x\n", key)
		fmt.Printf("NONCE: %x\n", nonce[:12])
		fmt.Printf("IN: %x\n", msg)
		fmt.Printf("AD: %x\n", ad)
		fmt.Printf("CT: %x\n", ct)
		fmt.Printf("TAG: %x\n", tag)
	}
}
