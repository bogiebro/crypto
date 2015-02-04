package test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/subtle"
	"hash"
	"testing"
)

func HashBench(b *testing.B, hash func() hash.Hash) {
	b.SetBytes(1024 * 1024)
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		h := hash()
		for j := 0; j < 1024; j++ {
			h.Write(data)
		}
		h.Sum(nil)
	}
}

// Benchmark a stream cipher.
func StreamCipherBench(b *testing.B, keylen int,
	cipher func([]byte) cipher.Stream) {
	key := make([]byte, keylen)
	b.SetBytes(1024 * 1024)
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		c := cipher(key)
		for j := 0; j < 1024; j++ {
			c.XORKeyStream(data, data)
		}
	}
}

// Benchmark a block cipher operating in counter mode.
/*
XXX Broken
func BlockCipherBench(b *testing.B, keylen int,
	bcipher func([]byte) cipher.Block) {
	StreamCipherBench(b, keylen, func(key []byte) cipher.Stream {
		bc := bcipher(key)
		iv := make([]byte, bc.BlockSize())
		return cipher.NewCTR(bc, iv)
	})
}
*/

// Compares the bits between two arrays returning the fraction
// of differences. If the two arrays are not of the same length
// no comparison is made and a -1 is returned.
func BitDiff(a, b []byte) float64 {
	if len(a) != len(b) {
		return -1
	}

	mask1 := byte(1)
	mask2 := byte(2)
	mask3 := byte(4)
	mask4 := byte(8)
	mask5 := byte(16)
	mask6 := byte(32)
	mask7 := byte(64)
	mask8 := byte(128)

	count := 0
	for i := 0; i < len(a); i++ {
		if (a[i] & mask1) != (b[i] & mask1) {
			count += 1
		}
		if (a[i] & mask2) != (b[i] & mask2) {
			count += 1
		}
		if (a[i] & mask3) != (b[i] & mask3) {
			count += 1
		}
		if (a[i] & mask4) != (b[i] & mask4) {
			count += 1
		}
		if (a[i] & mask5) != (b[i] & mask5) {
			count += 1
		}
		if (a[i] & mask6) != (b[i] & mask6) {
			count += 1
		}
		if (a[i] & mask7) != (b[i] & mask7) {
			count += 1
		}
		if (a[i] & mask8) != (b[i] & mask8) {
			count += 1
		}
	}

	return float64(count) / float64(len(a)*8)
}

// Tests a Cipher can encrypt and decrypt
func BCHelloWorldHelper(t *testing.T,
	newCipher func([]byte, ...interface{}) abstract.Cipher,
	n int, bitdiff float64) {
	text := []byte("Hello, World")
	cryptsize := len(text)
	decrypted := make([]byte, len(text))

	bc := newCipher(nil)
	keysize := bc.KeySize()

	nciphers := make([]abstract.Cipher, n)
	nkeys := make([][]byte, n)
	ncrypts := make([][]byte, n)

	for i := range nciphers {
		nkeys[i] = make([]byte, keysize)
		rand.Read(nkeys[i])
		bc = newCipher(nkeys[i])
		ncrypts[i] = make([]byte, cryptsize)
		bc.Message(ncrypts[i], text, nil)

		bc = newCipher(nkeys[i])
		bc.Message(decrypted, ncrypts[i], nil)
		if !bytes.Equal(text, decrypted) {
			t.Log("Encryption / Decryption failed", i)
			t.FailNow()
		}
	}

	for i := range ncrypts {
		for j := i + 1; j < len(ncrypts); j++ {
			if bytes.Equal(ncrypts[i], ncrypts[j]) {
				t.Log("Different keys result in same encryption")
				t.FailNow()
			}

			res := BitDiff(ncrypts[i], ncrypts[j])
			if res < bitdiff {
				t.Log("Encryptions not sufficiently different:", res)
				t.FailNow()
			}
		}
	}
}

// Tests a Cipher:
// 1) Encryption / decryption work
// 2) Encryption / decryption with different key don't work
// 3) Changing a bit in the ciphertext or mac results in failed mac check
// 4) Different keys produce sufficiently random output
func AuthenticateAndEncrypt(t *testing.T,
	newCipher func([]byte, ...interface{}) abstract.Cipher,
	n int, bitdiff float64, text []byte) {
	cryptsize := len(text)
	decrypted := make([]byte, len(text))

	bc := newCipher(nil)
	keysize := bc.KeySize()
	hashsize := bc.HashSize()
	mac := make([]byte, hashsize)

	nciphers := make([]abstract.Cipher, n)
	ncrypts := make([][]byte, n)
	nkeys := make([][]byte, n)
	nmacs := make([][]byte, n)

	// Encrypt / decrypt / mac test
	for i := range nciphers {
		nkeys[i] = make([]byte, keysize)
		rand.Read(nkeys[i])
		bc = newCipher(nkeys[i])
		ncrypts[i] = make([]byte, cryptsize)
		bc.Message(ncrypts[i], text, ncrypts[i])
		nmacs[i] = make([]byte, hashsize)
		bc.Message(nmacs[i], nil, nil)

		bc = newCipher(nkeys[i])
		bc.Message(decrypted, ncrypts[i], ncrypts[i])
		if !bytes.Equal(text, decrypted) {
			t.Log("Encryption / Decryption failed", i)
			t.FailNow()
		}

		mac = make([]byte, hashsize)
		bc.Message(nmacs[i], mac, nil)
		if subtle.ConstantTimeAllEq(mac, 0) != 1 {
			t.Log("MAC Check failed")
			t.FailNow()
		}
	}

	// Different keys test
	for i := range ncrypts {
		for j := range ncrypts {
			if i == j {
				continue
			}
			bc = newCipher(nkeys[i])
			bc.Message(decrypted, ncrypts[j], ncrypts[j])
			mac = make([]byte, hashsize)
			bc.Message(nmacs[j], mac, nil)
			if subtle.ConstantTimeAllEq(mac, 0) != 1 {
				t.Log("MAC Check passed")
				t.FailNow()
			}
		}
	}

	// Not enough randomness in 1 byte to pass this consistently
	if len(ncrypts[0]) < 2 {
		return
	}

	// Bit difference test
	for i := range ncrypts {
		for j := i + 1; j < len(ncrypts); j++ {
			res := BitDiff(ncrypts[i], ncrypts[j])
			if res < bitdiff {
				t.Log("Encryptions not sufficiently different", res)
				t.FailNow()
			}
		}
	}

	deltacopy := make([]byte, cryptsize)

	// Bit flipping test
	for i := range ncrypts {
		copy(ncrypts[i], deltacopy)

		deltacopy[0] ^= 255
		bc = newCipher(nkeys[i])
		bc.Message(decrypted, deltacopy, deltacopy)
		mac = make([]byte, hashsize)
		bc.Message(nmacs[i], mac, nil)
		if subtle.ConstantTimeAllEq(mac, 0) != 1 {
			t.Log("MAC Check passed")
			t.FailNow()
		}
		deltacopy[0] = ncrypts[i][0]

		deltacopy[len(deltacopy)/2-1] ^= 255
		bc = newCipher(nkeys[i])
		bc.Message(decrypted, deltacopy, deltacopy)
		mac = make([]byte, hashsize)
		bc.Message(nmacs[i], mac, nil)
		if subtle.ConstantTimeAllEq(mac, 0) != 1 {
			t.Log("MAC Check passed")
			t.FailNow()
		}
		deltacopy[len(deltacopy)/2-1] = ncrypts[i][len(deltacopy)/2-1]

		deltacopy[len(deltacopy)-1] ^= 255
		bc = newCipher(nkeys[i])
		bc.Message(decrypted, deltacopy, deltacopy)
		mac = make([]byte, hashsize)
		bc.Message(nmacs[i], mac, nil)
		if subtle.ConstantTimeAllEq(mac, 0) != 1 {
			t.Log("MAC Check passed")
			t.FailNow()
		}

		deltamac := make([]byte, hashsize)
		copy(nmacs[i], deltamac)
		deltamac[0] ^= 255
		bc = newCipher(nkeys[i])
		bc.Message(decrypted, ncrypts[i], ncrypts[i])
		mac = make([]byte, hashsize)
		bc.Message(deltamac, mac, nil)
		if subtle.ConstantTimeAllEq(mac, 0) != 1 {
			t.Log("MAC Check passed")
			t.FailNow()
		}
	}
}

// Iterate through various sized messages and verify
// that encryption and authentication work
func BCAuthenticatedEncryptionHelper(t *testing.T,
	newCipher func([]byte, ...interface{}) abstract.Cipher,
	n int, bitdiff float64) {
	AuthenticateAndEncrypt(t, newCipher, n, bitdiff, []byte{})
	AuthenticateAndEncrypt(t, newCipher, n, bitdiff, []byte{'a'})
	AuthenticateAndEncrypt(t, newCipher, n, bitdiff, []byte("Hello, World"))

	kb := make([]byte, 2^10)
	for i := 0; i < len(kb); i++ {
		kb[i] = byte(i & 256)
	}
	AuthenticateAndEncrypt(t, newCipher, n, bitdiff, kb)

	mb := make([]byte, 2^20)
	for i := 0; i < len(mb); i++ {
		mb[i] = byte(i & 256)
	}
	AuthenticateAndEncrypt(t, newCipher, n, bitdiff, mb)
}

func BlockCipherTest(t *testing.T,
	newCipher func([]byte, ...interface{}) abstract.Cipher) {
	n := 5
	bitdiff := .35
	BCHelloWorldHelper(t, newCipher, n, bitdiff)
	BCAuthenticatedEncryptionHelper(t, newCipher, n, bitdiff)
}
