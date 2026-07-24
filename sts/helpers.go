package sts

import (
	"bytes"
	"fmt"
	"math/rand"
	"regexp"
)

var awsTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// DecodeAID decodes the access key to extract Account ID.
func DecodeAID(accessKeyID string) (decodeAccountID string) {
	// Extract characters 3-12 (10 characters)
	if match, err := regexp.Match("A[K,S]IA[A-Z234567]{16}", []byte(accessKeyID)); err != nil || !match {
		return "000000000000"
	}
	paddedNo := accessKeyID[3:13]

	// Base32 decode
	var decimal uint64 = 0
	for _, char := range paddedNo {
		index := bytes.IndexByte([]byte(awsTable), byte(char))
		decimal = (decimal << 5) + uint64(index)
	}

	// Shift right by 4 bits and mask with 40-bit mask
	mask := uint64((1 << 40) - 1)
	decimal = (decimal >> 4) & mask

	// Format as 12-digit string with leading zeros
	return fmt.Sprintf("%012d", decimal)
}

func CreateNewKey(accessKeyID string) (newAccessKeyID string) {
	// AKIA 7TKC4YKJ7T KMSEA 7
	keyStr := make([]byte, 5)
	for i := range 5 {
		keyStr[i] = awsTable[rand.Intn(32)]
	}
	newAccessKeyID = "AKIA" + accessKeyID[4:14] + string(keyStr) + accessKeyID[19:]
	return newAccessKeyID
}

// UserNames contains a list of common cryptographic protocol participant names.
var UserNames = [...]string{
	"Alice",
	"Bob",
	"Carol",
	"Dave",
	"Eve",
	"Frank",
	"Grace",
	"Heidi",
	"Ivan",
	"Judy",
	"Mallory",
	"Oscar",
	"Trent",
	"Walter",
	"Peggy",
	"Victor",
}

// GetFakeUser picks a "user" based on last digit of access key
func GetFakeUser(accessKey string) (name string) {
	if accessKey == "" {
		return "Invalid"
	}
	bstr := []byte(accessKey)
	index := bytes.IndexByte([]byte(awsTable), byte(bstr[len(bstr)-1]))
	if index < 0 {
		return "Invalid"
	}
	index = index & 0x0f
	return UserNames[index]
}
