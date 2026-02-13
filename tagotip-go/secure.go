package tagotip

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	headerSize         = 21
	authHashSize       = 8
	deviceHashSize     = 8
	flagsSize          = 1
	counterSize        = 4
	ccmTagSize         = 8
	ccmNonceSize       = 13
	maxInnerFrameSize  = 16_384
	reservedFlagsValue = 0x41

	flagsCipherMask  = 0b1110_0000
	flagsCipherShift = 5
	flagsVersionMask = 0b0001_1000
	flagsVersionShift = 3
	flagsMethodMask  = 0b0000_0111
)

// CipherSuite represents the AEAD cipher suite.
type CipherSuite int

const (
	CipherSuiteAes128Ccm CipherSuite = 0
)

// EnvelopeMethod represents the method in the envelope flags.
type EnvelopeMethod int

const (
	EnvelopeMethodPush EnvelopeMethod = 0
	EnvelopeMethodPull EnvelopeMethod = 1
	EnvelopeMethodPing EnvelopeMethod = 2
	EnvelopeMethodAck  EnvelopeMethod = 3
)

// EnvelopeHeader represents the parsed 21-byte envelope header.
type EnvelopeHeader struct {
	Flags      byte
	Counter    uint32
	AuthHash   [authHashSize]byte
	DeviceHash [deviceHashSize]byte
}

// SecureError represents an error from crypto envelope operations.
type SecureError struct {
	Message string
}

func (e *SecureError) Error() string {
	return fmt.Sprintf("tagotips: %s", e.Message)
}

func secureErr(msg string) error {
	return &SecureError{Message: msg}
}

// DeriveAuthHash derives the Authorization Hash from a token.
// The token format is "at" + 32 hex chars. The "at" prefix is stripped,
// and SHA-256 is computed over the remaining hex string (UTF-8 encoded).
// Returns the first 8 bytes of the digest.
func DeriveAuthHash(token string) [authHashSize]byte {
	hexPart := token
	if len(token) > 2 && token[0] == 'a' && token[1] == 't' {
		hexPart = token[2:]
	}
	digest := sha256.Sum256([]byte(hexPart))
	var hash [authHashSize]byte
	copy(hash[:], digest[:authHashSize])
	return hash
}

// DeriveDeviceHash derives the Device Hash from a serial number.
// Computes SHA-256 of the serial (UTF-8 encoded) and returns the first 8 bytes.
func DeriveDeviceHash(serial string) [deviceHashSize]byte {
	digest := sha256.Sum256([]byte(serial))
	var hash [deviceHashSize]byte
	copy(hash[:], digest[:deviceHashSize])
	return hash
}

// DeriveKey derives an encryption key from a token and serial using HMAC-SHA256.
// The "at" prefix is stripped from the token. The remaining hex string (UTF-8)
// is used as the HMAC key; the serial (UTF-8) is the HMAC message.
// keyLen must be 16 (AES-128) or 32 (AES-256/ChaCha20).
func DeriveKey(token, serial string, keyLen int) ([]byte, error) {
	if keyLen != 16 && keyLen != 32 {
		return nil, secureErr("key length must be 16 or 32")
	}
	hexPart := token
	if strings.HasPrefix(token, "at") {
		hexPart = token[2:]
	}
	mac := hmac.New(sha256.New, []byte(hexPart))
	mac.Write([]byte(serial))
	fullKey := mac.Sum(nil)
	return fullKey[:keyLen], nil
}

// HexToBytes decodes a hex string into bytes.
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

// BytesToHex encodes bytes as a lowercase hex string.
func BytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

func encodeFlags(cipherID, version, methodID int) (byte, error) {
	flags := byte((cipherID << flagsCipherShift) | (version << flagsVersionShift) | methodID)
	if flags == reservedFlagsValue {
		return 0, secureErr("flags byte 0x41 is reserved")
	}
	return flags, nil
}

func decodeFlags(flags byte) (cipherID, version, methodID int, err error) {
	if flags == reservedFlagsValue {
		return 0, 0, 0, secureErr("flags byte 0x41 is reserved")
	}
	cipherID = int((flags & flagsCipherMask) >> flagsCipherShift)
	version = int((flags & flagsVersionMask) >> flagsVersionShift)
	methodID = int(flags & flagsMethodMask)
	return cipherID, version, methodID, nil
}

func buildEnvelopeHeader(flags byte, counter uint32, authHash [authHashSize]byte, deviceHash [deviceHashSize]byte) []byte {
	header := make([]byte, headerSize)
	header[0] = flags
	binary.BigEndian.PutUint32(header[flagsSize:], counter)
	copy(header[flagsSize+counterSize:], authHash[:])
	copy(header[flagsSize+counterSize+authHashSize:], deviceHash[:])
	return header
}

func constructNonce(flags byte, deviceHash [deviceHashSize]byte, counter uint32) []byte {
	nonce := make([]byte, ccmNonceSize)
	nonce[0] = flags
	// Zero padding at bytes 1-4 (already zeroed)
	// Device hash first 4 bytes at offset (13 - 8) = 5
	copy(nonce[ccmNonceSize-8:ccmNonceSize-4], deviceHash[:4])
	// Counter as big-endian u32 in last 4 bytes
	binary.BigEndian.PutUint32(nonce[ccmNonceSize-4:], counter)
	return nonce
}

// ccmEncrypt performs AES-128-CCM encryption with 8-byte tag.
func ccmEncrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, secureErr("invalid encryption key")
	}
	return ccmSeal(block, nonce, aad, plaintext)
}

// ccmDecrypt performs AES-128-CCM decryption with 8-byte tag.
func ccmDecrypt(key, nonce, aad, ciphertextWithTag []byte) ([]byte, error) {
	if len(ciphertextWithTag) < ccmTagSize {
		return nil, secureErr("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, secureErr("invalid encryption key")
	}
	return ccmOpen(block, nonce, aad, ciphertextWithTag)
}

// SealUplink encrypts a headless inner frame into a TagoTiP/S uplink envelope.
func SealUplink(
	method EnvelopeMethod,
	innerFrame []byte,
	counter uint32,
	authHash [authHashSize]byte,
	deviceHash [deviceHashSize]byte,
	key []byte,
	suite CipherSuite,
) ([]byte, error) {
	if len(innerFrame) > maxInnerFrameSize {
		return nil, secureErr("inner frame exceeds maximum size")
	}
	if suite != CipherSuiteAes128Ccm {
		return nil, secureErr("unsupported cipher suite")
	}
	if len(key) != 16 {
		return nil, secureErr("invalid encryption key size")
	}

	flags, err := encodeFlags(int(suite), 0, int(method))
	if err != nil {
		return nil, err
	}

	header := buildEnvelopeHeader(flags, counter, authHash, deviceHash)
	nonce := constructNonce(flags, deviceHash, counter)

	ciphertextWithTag, err := ccmEncrypt(key, nonce, header, innerFrame)
	if err != nil {
		return nil, err
	}

	envelope := make([]byte, headerSize+len(ciphertextWithTag))
	copy(envelope, header)
	copy(envelope[headerSize:], ciphertextWithTag)
	return envelope, nil
}

// OpenEnvelope decrypts a TagoTiP/S envelope.
// Returns the header, method, and decrypted inner frame bytes.
func OpenEnvelope(envelope, key []byte) (*EnvelopeHeader, EnvelopeMethod, []byte, error) {
	header, err := ParseEnvelopeHeader(envelope)
	if err != nil {
		return nil, 0, nil, err
	}

	cipherID, version, methodID, err := decodeFlags(header.Flags)
	if err != nil {
		return nil, 0, nil, err
	}

	if version != 0 {
		return nil, 0, nil, secureErr("unsupported version")
	}
	if cipherID != 0 {
		return nil, 0, nil, secureErr("unsupported cipher suite")
	}
	if methodID > 3 {
		return nil, 0, nil, secureErr("invalid method")
	}
	if len(key) != 16 {
		return nil, 0, nil, secureErr("invalid encryption key size")
	}

	ciphertextWithTag := envelope[headerSize:]
	if len(ciphertextWithTag) < ccmTagSize {
		return nil, 0, nil, secureErr("envelope too short")
	}

	aad := envelope[:headerSize]
	nonce := constructNonce(header.Flags, header.DeviceHash, header.Counter)

	plaintext, err := ccmDecrypt(key, nonce, aad, ciphertextWithTag)
	if err != nil {
		return nil, 0, nil, err
	}

	return header, EnvelopeMethod(methodID), plaintext, nil
}

// ParseEnvelopeHeader parses the 21-byte envelope header for server-side routing.
func ParseEnvelopeHeader(envelope []byte) (*EnvelopeHeader, error) {
	if len(envelope) < headerSize {
		return nil, secureErr("envelope too short")
	}

	flags := envelope[0]
	if _, _, _, err := decodeFlags(flags); err != nil {
		return nil, err
	}

	counter := binary.BigEndian.Uint32(envelope[flagsSize:])
	var authHash [authHashSize]byte
	copy(authHash[:], envelope[flagsSize+counterSize:])
	var deviceHash [deviceHashSize]byte
	copy(deviceHash[:], envelope[flagsSize+counterSize+authHashSize:])

	return &EnvelopeHeader{
		Flags:      flags,
		Counter:    counter,
		AuthHash:   authHash,
		DeviceHash: deviceHash,
	}, nil
}

// IsEnvelope checks if a message is a TagoTiP/S envelope or a plaintext fallback.
// Returns true if the first byte is NOT 0x41 (ASCII 'A').
func IsEnvelope(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0] != reservedFlagsValue
}

// IsSecureError checks if an error is a SecureError.
func IsSecureError(err error) bool {
	var se *SecureError
	return errors.As(err, &se)
}
