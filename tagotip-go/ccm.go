package tagotip

import (
	"crypto/cipher"
	"crypto/subtle"
)

// AES-128-CCM implementation per NIST SP 800-38C.
// Parameters: tag size = 8 bytes, L = 2, nonce = 13 bytes.

const (
	ccmL     = 2      // length field size in bytes
	ccmBlock = 16     // AES block size
)

// ccmSeal encrypts plaintext and produces ciphertext || tag.
func ccmSeal(block cipher.Block, nonce, aad, plaintext []byte) ([]byte, error) {
	if len(nonce) != ccmNonceSize {
		return nil, secureErr("invalid nonce size")
	}

	tag := ccmCBCMAC(block, nonce, aad, plaintext)
	ciphertext := make([]byte, len(plaintext)+ccmTagSize)

	// CTR encryption of plaintext
	ccmCTR(block, nonce, ciphertext[:len(plaintext)], plaintext)

	// Encrypt the tag with CTR counter = 0
	var a0 [ccmBlock]byte
	a0[0] = byte(ccmL - 1) // flags for A0
	copy(a0[1:], nonce)
	// Counter bytes at end are 0 (already zeroed)

	var s0 [ccmBlock]byte
	block.Encrypt(s0[:], a0[:])

	// XOR tag with S0 to produce encrypted tag
	for i := 0; i < ccmTagSize; i++ {
		ciphertext[len(plaintext)+i] = tag[i] ^ s0[i]
	}

	return ciphertext, nil
}

// ccmOpen decrypts ciphertext || tag and verifies the tag.
func ccmOpen(block cipher.Block, nonce, aad, ciphertextWithTag []byte) ([]byte, error) {
	if len(nonce) != ccmNonceSize {
		return nil, secureErr("invalid nonce size")
	}
	if len(ciphertextWithTag) < ccmTagSize {
		return nil, secureErr("ciphertext too short")
	}

	ctLen := len(ciphertextWithTag) - ccmTagSize
	ciphertext := ciphertextWithTag[:ctLen]
	encTag := ciphertextWithTag[ctLen:]

	// Decrypt the tag with CTR counter = 0
	var a0 [ccmBlock]byte
	a0[0] = byte(ccmL - 1)
	copy(a0[1:], nonce)

	var s0 [ccmBlock]byte
	block.Encrypt(s0[:], a0[:])

	var receivedTag [ccmTagSize]byte
	for i := 0; i < ccmTagSize; i++ {
		receivedTag[i] = encTag[i] ^ s0[i]
	}

	// CTR decrypt the ciphertext
	plaintext := make([]byte, ctLen)
	ccmCTR(block, nonce, plaintext, ciphertext)

	// Compute expected tag
	expectedTag := ccmCBCMAC(block, nonce, aad, plaintext)

	// Constant-time comparison
	if subtle.ConstantTimeCompare(receivedTag[:], expectedTag[:]) != 1 {
		return nil, secureErr("AEAD decryption failed")
	}

	return plaintext, nil
}

// ccmCBCMAC computes the CBC-MAC authentication tag.
func ccmCBCMAC(block cipher.Block, nonce, aad, plaintext []byte) [ccmTagSize]byte {
	// Build B0 block
	var b0 [ccmBlock]byte
	flags := byte(0)
	if len(aad) > 0 {
		flags |= 1 << 6 // Adata flag
	}
	flags |= byte((ccmTagSize/2 - 1) << 3) // t field: (tagSize-2)/2
	flags |= byte(ccmL - 1)                  // q field: L-1
	b0[0] = flags
	copy(b0[1:], nonce)

	// Encode message length in last L bytes (big-endian)
	msgLen := len(plaintext)
	for i := 0; i < ccmL; i++ {
		b0[ccmBlock-1-i] = byte(msgLen >> (8 * i))
	}

	// Start CBC-MAC
	var x [ccmBlock]byte
	xorBlock(&x, b0[:])
	block.Encrypt(x[:], x[:])

	// Encode AAD
	if len(aad) > 0 {
		// For aad length < 2^16 - 2^8, encode as 2-byte length
		var aadHeader [2]byte
		aadHeader[0] = byte(len(aad) >> 8)
		aadHeader[1] = byte(len(aad))

		// Process aad header + aad data
		aadBuf := make([]byte, 0, 2+len(aad))
		aadBuf = append(aadBuf, aadHeader[:]...)
		aadBuf = append(aadBuf, aad...)

		// Pad to block boundary
		padLen := (ccmBlock - len(aadBuf)%ccmBlock) % ccmBlock
		for range padLen {
			aadBuf = append(aadBuf, 0)
		}

		for i := 0; i < len(aadBuf); i += ccmBlock {
			xorBlock(&x, aadBuf[i:i+ccmBlock])
			block.Encrypt(x[:], x[:])
		}
	}

	// Process plaintext blocks
	if len(plaintext) > 0 {
		full := (len(plaintext) / ccmBlock) * ccmBlock
		for i := 0; i < full; i += ccmBlock {
			xorBlock(&x, plaintext[i:i+ccmBlock])
			block.Encrypt(x[:], x[:])
		}
		// Handle last partial block
		if full < len(plaintext) {
			var lastBlock [ccmBlock]byte
			copy(lastBlock[:], plaintext[full:])
			xorBlock(&x, lastBlock[:])
			block.Encrypt(x[:], x[:])
		}
	}

	var tag [ccmTagSize]byte
	copy(tag[:], x[:ccmTagSize])
	return tag
}

// ccmCTR performs CTR encryption/decryption starting at counter = 1.
func ccmCTR(block cipher.Block, nonce []byte, dst, src []byte) {
	var a [ccmBlock]byte
	a[0] = byte(ccmL - 1)
	copy(a[1:], nonce)

	var keystream [ccmBlock]byte
	counter := uint16(1) // Start at counter 1 for data

	for i := 0; i < len(src); i += ccmBlock {
		// Set counter bytes (big-endian, last L bytes)
		a[ccmBlock-2] = byte(counter >> 8)
		a[ccmBlock-1] = byte(counter)
		block.Encrypt(keystream[:], a[:])

		end := i + ccmBlock
		if end > len(src) {
			end = len(src)
		}
		for j := i; j < end; j++ {
			dst[j] = src[j] ^ keystream[j-i]
		}
		counter++
	}
}

func xorBlock(dst *[ccmBlock]byte, src []byte) {
	for i := 0; i < ccmBlock && i < len(src); i++ {
		dst[i] ^= src[i]
	}
}
