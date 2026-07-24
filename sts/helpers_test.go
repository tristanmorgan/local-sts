package sts

import (
	"regexp"
	"testing"
)

func TestDecodeAID(t *testing.T) {
	tests := []struct {
		name       string
		accessKey  string
		expectedID string
	}{
		{
			name:       "Valid access key - AKIAZOXKDENHR2JTNJLI",
			accessKey:  "AKIAZOXKDENHR2JTNJLI",
			expectedID: "650104742735",
		},
		{
			name:       "Valid access key - AKIASIFCFAPDEMQNV3SO",
			accessKey:  "AKIASIFCFAPDEMQNV3SO",
			expectedID: "154958889926",
		},
		{
			name:       "Valid access key - AKIA5L7HQJMWG3EHBA3J",
			accessKey:  "AKIA5L7HQJMWG3EHBA3J",
			expectedID: "919071640364",
		},
		{
			name:       "Valid session key - ASIATMOLCWJCZGCXWWRF",
			accessKey:  "ASIATMOLCWJCZGCXWWRF",
			expectedID: "232891003461",
		},
		{
			name:       "Invalid access key - AKIAI44QH8DHBEXAMPLE",
			accessKey:  "AKIAI44QH8DHBEXAMPLE",
			expectedID: "000000000000",
		},
		{
			name:       "Short access key",
			accessKey:  "AKIA",
			expectedID: "000000000000",
		},
		{
			name:       "Empty access key",
			accessKey:  "",
			expectedID: "000000000000",
		},
		{
			name:       "Access key with invalid characters",
			accessKey:  "AKIA!!!INVALID!!!",
			expectedID: "000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecodeAID(tt.accessKey)
			if result != tt.expectedID {
				t.Errorf("DecodeAID(%q) = %q, want %q", tt.accessKey, result, tt.expectedID)
			}
		})
	}
}

func BenchmarkDecodeAID(b *testing.B) {
	accessKey := "AKIAZOXKDENHR2JTNJLI"
	for i := 0; i < b.N; i++ {
		DecodeAID(accessKey)
	}
}

func TestGetFakeUser(t *testing.T) {
	tests := []struct {
		name         string
		accessKey    string
		expectedUser string
	}{
		{
			name:         "Access key ending with I - Ivan",
			accessKey:    "AKIAZOXKDENHR2JTNJLI",
			expectedUser: "Ivan",
		},
		{
			name:         "Access key ending with O - Peggy",
			accessKey:    "AKIASIFCFAPDEMQNV3SO",
			expectedUser: "Peggy",
		},
		{
			name:         "Access key ending with J - Judy",
			accessKey:    "AKIA5L7HQJMWG3EHBA3J",
			expectedUser: "Judy",
		},
		{
			name:         "Access key ending with F - Frank",
			accessKey:    "ASIADVUE6CL3HNEWV6SF",
			expectedUser: "Frank",
		},
		{
			name:         "Access key ending with 7 - Victor",
			accessKey:    "AKIAZOXKDENHR2JTNJL7",
			expectedUser: "Victor",
		},
		{
			name:         "Empty access key returns Invalid",
			accessKey:    "",
			expectedUser: "Invalid",
		},
		{
			name:         "Access key with invalid character returns Invalid",
			accessKey:    "AKIAZOXKDENHR2JTNJL!",
			expectedUser: "Invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetFakeUser(tt.accessKey)
			if result != tt.expectedUser {
				t.Errorf("GetFakeUser(%q) = %q, want %q", tt.accessKey, result, tt.expectedUser)
			}
		})
	}
}

func TestCreateNewKey(t *testing.T) {
	tests := []struct {
		name            string
		inputAccessKey  string
		expectedPattern string
		description     string
	}{
		{
			name:            "Valid AKIA key",
			inputAccessKey:  "AKIAZOXKDENHR2JTNJLI",
			expectedPattern: "^AKIAZOXKDENHR[A-Z234567]{6}I$",
			description:     "Should preserve AKIA prefix, chars 4-14, and last char",
		},
		{
			name:            "Valid ASIA key",
			inputAccessKey:  "ASIATMOLCWJCZGCXWWRF",
			expectedPattern: "^AKIATMOLCWJCZG[A-Z234567]{5}F$",
			description:     "Should convert ASIA to AKIA and preserve structure",
		},
		{
			name:            "Another valid key",
			inputAccessKey:  "AKIASIFCFAPDEMQNV3SO",
			expectedPattern: "^AKIASIFCFAPDEM[A-Z234567]{5}O$",
			description:     "Should maintain account ID portion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CreateNewKey(tt.inputAccessKey)

			// Check the result matches the expected pattern
			matched, err := regexp.MatchString(tt.expectedPattern, result)
			if err != nil {
				t.Fatalf("Invalid regex pattern: %v", err)
			}
			if !matched {
				t.Errorf("CreateNewKey(%q) = %q, does not match pattern %q\n%s",
					tt.inputAccessKey, result, tt.expectedPattern, tt.description)
			}

			// Verify length is 20 characters
			if len(result) != 20 {
				t.Errorf("CreateNewKey(%q) length = %d, want 20", tt.inputAccessKey, len(result))
			}

			// Verify it starts with AKIA
			if result[:4] != "AKIA" {
				t.Errorf("CreateNewKey(%q) should start with AKIA, got %q", tt.inputAccessKey, result[:4])
			}

			// Verify the account ID portion (chars 4-14) is preserved
			if result[4:14] != tt.inputAccessKey[4:14] {
				t.Errorf("CreateNewKey(%q) account ID portion = %q, want %q",
					tt.inputAccessKey, result[4:14], tt.inputAccessKey[4:14])
			}

			// Verify the last character is preserved
			if result[19] != tt.inputAccessKey[19] {
				t.Errorf("CreateNewKey(%q) last char = %c, want %c",
					tt.inputAccessKey, result[19], tt.inputAccessKey[19])
			}
		})
	}
}

func TestCreateNewKeyRandomness(t *testing.T) {
	// Test that CreateNewKey generates different keys on multiple calls
	inputKey := "AKIAZOXKDENHR2JTNJLI"
	keys := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		newKey := CreateNewKey(inputKey)
		keys[newKey] = true
	}

	// We expect at least some variation (not all identical)
	// With 5 random characters from 32 possibilities, we should see variety
	if len(keys) < 10 {
		t.Errorf("CreateNewKey should generate varied keys, got only %d unique keys in %d iterations",
			len(keys), iterations)
	}
}

func TestCreateNewKeyPreservesAccountID(t *testing.T) {
	// Test that the account ID can still be decoded from the new key
	originalKey := "AKIAZOXKDENHR2JTNJLI"
	originalAccountID := DecodeAID(originalKey)

	newKey := CreateNewKey(originalKey)
	newAccountID := DecodeAID(newKey)

	if originalAccountID != newAccountID {
		t.Errorf("CreateNewKey should preserve account ID: original=%q, new=%q",
			originalAccountID, newAccountID)
	}
}

func BenchmarkCreateNewKey(b *testing.B) {
	accessKey := "AKIAZOXKDENHR2JTNJLI"
	for i := 0; i < b.N; i++ {
		CreateNewKey(accessKey)
	}
}
