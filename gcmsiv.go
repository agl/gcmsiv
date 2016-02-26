package gcmsiv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// fieldElement represents a binary polynomial. The elements are in
// little-endian order, i.e the polynomial 'x' would be {1, 0, 0, 0}.
type fieldElement [4]uint64

var (
	// irreduciblePolynomial is the irreducable polynomial that defines the
	// field in which POLYVAL operates.
	irreduciblePolynomial = fieldElement([4]uint64{
		1, 0xc200000000000000, 1, 0,
	})
	// xMinus128 is the representation of x^-128.
	xMinus128 = fieldElement([4]uint64{
		1, 0x9204000000000000, 0, 0,
	})
)

// fieldElementFromBytes converts 16 bytes into a field element.
func fieldElementFromBytes(bytes []byte) fieldElement {
	return fieldElement([4]uint64{
		binary.LittleEndian.Uint64(bytes[:8]),
		binary.LittleEndian.Uint64(bytes[8:16]),
		0,
		0,
	})
}

// fitsIn128Bits returns true if the top 128 bits of f are all zero. (And thus
// the value itself fits in 128 bits.)
func (f fieldElement) fitsIn128Bits() bool {
	return f[2] == 0 && f[3] == 0
}

// Bytes returns f as a 16-byte string. It requires that f fit into 128 bits.
func (f fieldElement) Bytes() (ret [16]byte) {
	if !f.fitsIn128Bits() {
		panic("Bytes argument out of range")
	}

	binary.LittleEndian.PutUint64(ret[:8], f[0])
	binary.LittleEndian.PutUint64(ret[8:], f[1])

	return ret
}

func (f fieldElement) String() string {
	if f.fitsIn128Bits() {
		return fmt.Sprintf("%016x%016x", f[1], f[0])
	} else {
		return fmt.Sprintf("%016x%016x%016x%016x",
			f[3], f[2], f[1], f[0])
	}
}

// coefficient returns the coefficient of x^i in f.
func (f fieldElement) coefficient(i uint) bool {
	return (f[(i/64)]>>(i&63))&1 == 1
}

// leftShift returns f times x^i.
func (f fieldElement) leftShift(i uint) (result fieldElement) {
	// 0 <= i < 128
	if i < 64 {
		copy(result[:], f[:])
	} else if i < 128 {
		result[1] = f[0]
		result[2] = f[1]
		result[3] = f[2]
		i -= 64
	} else {
		panic("leftShift argument out of range")
	}

	result[3] = result[3]<<i | result[2]>>(64-i)
	result[2] = result[2]<<i | result[1]>>(64-i)
	result[1] = result[1]<<i | result[0]>>(64-i)
	result[0] = result[0] << i

	return result
}

func (a fieldElement) add(b fieldElement) (result fieldElement) {
	result[0] = a[0] ^ b[0]
	result[1] = a[1] ^ b[1]
	result[2] = a[2] ^ b[2]
	result[3] = a[3] ^ b[3]
	return result
}

func (a fieldElement) mul(b fieldElement) fieldElement {
	var product fieldElement

	if !a.fitsIn128Bits() || !b.fitsIn128Bits() {
		panic("mul argument out of range")
	}

	for i := uint(0); i < 128; i++ {
		if b.coefficient(127 - i) {
			shifted := a.leftShift(127 - i)
			for i := range product {
				product[i] ^= shifted[i]
			}
		}
	}

	// Reduce modulo the irreducable polynomial that defines the field.
	for i := uint(0); i < 128; i++ {
		if product.coefficient(255 - i) {
			shifted := irreduciblePolynomial.leftShift(127 - i)
			product = product.add(shifted)
		}
	}

	if !product.fitsIn128Bits() {
		panic("internal error")
	}

	return product
}

func (a fieldElement) dot(b fieldElement) fieldElement {
	return a.mul(b).mul(xMinus128)
}

func polyval(hBytes [16]byte, input []byte) [16]byte {
	if len(input)%16 != 0 {
		panic("polyval input not a multiple of the block size")
	}

	h := fieldElementFromBytes(hBytes[:])
	var s fieldElement

	for len(input) > 0 {
		x := fieldElementFromBytes(input[:16])
		input = input[16:]

		s = s.add(x).dot(h)
	}

	return s.Bytes()
}

const (
	maxPlaintextLen  = 1 << 36
	maxCiphertextLen = maxPlaintextLen + 16
	maxADLen         = (1 << 61) - 1
)

type GCMSIV struct {
	hBytes   [16]byte
	block    cipher.Block
	is256Bit bool
}

func (GCMSIV) NonceSize() int {
	return 16
}

func (GCMSIV) Overhead() int {
	return 16
}

func NewGCMSIV(key []byte) (*GCMSIV, error) {
	var block cipher.Block
	var err error
	is256Bit := false

	switch len(key) {
	case 48:
		is256Bit = true
		fallthrough

	case 32:
		if block, err = aes.NewCipher(key[16:]); err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("gcmsiv: bad key length")
	}

	ret := &GCMSIV{
		block:    block,
		is256Bit: is256Bit,
	}
	copy(ret.hBytes[:], key[:16])

	return ret, nil
}

func appendU64(a []byte, val int) []byte {
	var valBytes [8]byte
	binary.LittleEndian.PutUint64(valBytes[:], uint64(val))
	return append(a, valBytes[:]...)
}

func (ctx *GCMSIV) deriveRecordEncryptionKey(nonce []byte) cipher.Block {
	if !ctx.is256Bit {
		var recordKey [16]byte
		ctx.block.Encrypt(recordKey[:], nonce)
		block, _ := aes.NewCipher(recordKey[:])
		return block
	}

	var nonceCopy [16]byte
	copy(nonceCopy[:], nonce)

	var recordKey [32]byte
	nonceCopy[0] &= 0xfe
	ctx.block.Encrypt(recordKey[:], nonceCopy[:])

	nonceCopy[0] |= 1
	ctx.block.Encrypt(recordKey[16:], nonceCopy[:])

	block, _ := aes.NewCipher(recordKey[:])
	return block
}

func (ctx *GCMSIV) calculateTag(additionalData, plaintext []byte, nonce []byte, block cipher.Block) [16]byte {
	input := make([]byte, 0, len(additionalData)+len(plaintext)+48)

	input = append(input, additionalData...)
	for len(input)%16 != 0 {
		input = append(input, 0)
	}

	input = append(input, plaintext...)
	for len(input)%16 != 0 {
		input = append(input, 0)
	}

	input = appendU64(input, len(additionalData)*8)
	input = appendU64(input, len(plaintext)*8)

	S_s := polyval(ctx.hBytes, input)
	for i := range S_s {
		S_s[i] ^= nonce[i]
	}

	S_s[15] &= 0x7f
	block.Encrypt(S_s[:], S_s[:])

	return S_s
}

func cryptBytes(dst, src, initCtr []byte, block cipher.Block) []byte {
	var ctrBlock, keystreamBlock [16]byte
	copy(ctrBlock[:], initCtr)
	ctrBlock[15] |= 0x80

	for ctr := uint32(1); len(src) > 0; ctr += 1 {
		binary.LittleEndian.PutUint32(ctrBlock[:], ctr)
		block.Encrypt(keystreamBlock[:], ctrBlock[:])

		plaintextBlock := src
		if len(plaintextBlock) > 16 {
			plaintextBlock = plaintextBlock[:16]
		}
		src = src[len(plaintextBlock):]

		for i := range plaintextBlock {
			dst = append(dst, plaintextBlock[i]^keystreamBlock[i])
		}
	}

	return dst
}

func (ctx *GCMSIV) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(plaintext) > maxPlaintextLen {
		panic("gcmsiv: plaintext too large")
	}

	if len(additionalData) > maxADLen {
		panic("gcmsiv: additional data too large")
	}

	block := ctx.deriveRecordEncryptionKey(nonce)
	tag := ctx.calculateTag(additionalData, plaintext, nonce, block)
	dst = cryptBytes(dst, plaintext, tag[:], block)
	return append(dst, tag[:]...)
}

func (ctx GCMSIV) Open(dst, nonce, ciphertext, additionalData []byte) (out []byte, err error) {
	if len(additionalData) > maxADLen {
		return nil, errors.New("gcmsiv: bad ciphertext length")
	}

	if len(ciphertext) < 16 || len(ciphertext) > maxCiphertextLen {
		return nil, errors.New("gcmsiv: bad ciphertext length")
	}

	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	initialDstLen := len(dst)
	block := ctx.deriveRecordEncryptionKey(nonce)
	dst = cryptBytes(dst, ciphertext, tag, block)
	calculatedTag := ctx.calculateTag(additionalData, dst[initialDstLen:], nonce, block)
	if subtle.ConstantTimeCompare(calculatedTag[:], tag) != 1 {
		return nil, errors.New("gcmsiv: decryption failure")
	}

	return dst, nil
}
