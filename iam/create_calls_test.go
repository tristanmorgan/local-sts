package iam

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateAccessKey(t *testing.T) {
	tests := []struct {
		name         string
		authHeader   string
		wantStatus   int
		wantContains []string
	}{
		{
			name:       "Valid request",
			authHeader: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...",
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<CreateAccessKeyResponse",
				"<AccessKeyId>AKIAIOSFODNN7",
				"<Status>Active</Status>",
				"<SecretAccessKey>",
				"<UserName>",
				"<ResponseMetadata>",
				"<RequestId>",
			},
		},
		{
			name:       "Missing authorization",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantContains: []string{
				"<ErrorResponse",
				"<Code>InvalidClientTokenId",
			},
		},
		{
			name:       "Invalid authorization format",
			authHeader: "Bearer invalid",
			wantStatus: http.StatusUnauthorized,
			wantContains: []string{
				"<ErrorResponse",
				"<Code>InvalidClientTokenId",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/?Action=CreateAccessKey&Version=2010-05-08", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			CreateAccessKey(w, req, "requ-esti-duuid")

			if w.Code != tt.wantStatus {
				t.Errorf("CreateAccessKey() status = %v, want %v", w.Code, tt.wantStatus)
			}

			body := w.Body.String()
			for _, want := range tt.wantContains {
				if !contains(body, want) {
					t.Errorf("CreateAccessKey() body should contain %q, got %q", want, body)
				}
			}
		})
	}
}

func TestCreateAccessKeySecretGeneration(t *testing.T) {
	// Test that the secret key is properly generated using base64 encoding
	req := httptest.NewRequest(http.MethodPost, "/?Action=CreateAccessKey&Version=2010-05-08", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...")

	w := httptest.NewRecorder()
	CreateAccessKey(w, req, "requ-esti-duuid")

	body := w.Body.String()

	// Verify the response contains an access key starting with AKIA
	if !contains(body, "<AccessKeyId>AKIA") {
		t.Errorf("CreateAccessKey() response should contain access key starting with AKIA")
	}

	// Verify the response contains a base64-encoded secret key
	// The secret should be base64 encoded and contain the pattern
	if !strings.Contains(body, "<SecretAccessKey>") {
		t.Errorf("CreateAccessKey() response should contain SecretAccessKey tag")
	}

	// Extract and verify the secret key is base64 encoded
	start := strings.Index(body, "<SecretAccessKey>")
	end := strings.Index(body, "</SecretAccessKey>")
	if start != -1 && end != -1 {
		secretKey := body[start+len("<SecretAccessKey>") : end]
		// Base64 strings should only contain alphanumeric, +, /, and = characters
		for _, char := range secretKey {
			if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') || char == '+' || char == '/' || char == '=') {
				t.Errorf("CreateAccessKey() secret key contains invalid base64 character: %c", char)
			}
		}
	}
}

func TestCreateAccessKeyVarsTemplate(t *testing.T) {
	// Test that the template variables are correctly used
	req := httptest.NewRequest(http.MethodPost, "/?Action=CreateAccessKey&Version=2010-05-08", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...")

	w := httptest.NewRecorder()
	CreateAccessKey(w, req, "requ-esti-duuid")

	body := w.Body.String()

	// Verify the response contains expected structure
	expectedValues := []string{
		"<CreateAccessKeyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">",
		"<CreateAccessKeyResult>",
		"<AccessKey>",
		"<Status>Active</Status>",
	}

	for _, expected := range expectedValues {
		if !contains(body, expected) {
			t.Errorf("CreateAccessKey() response should contain %q", expected)
		}
	}
}

func TestCreateAccessKeyResponseStructure(t *testing.T) {
	// Test that the response has the correct XML structure
	req := httptest.NewRequest(http.MethodPost, "/?Action=CreateAccessKey&Version=2010-05-08", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...")

	w := httptest.NewRecorder()
	CreateAccessKey(w, req, "requ-esti-duuid")

	body := w.Body.String()

	// Verify the response has proper XML structure
	if !strings.Contains(body, "<?xml") && !strings.Contains(body, "<CreateAccessKeyResponse") {
		t.Log("Response might be missing XML declaration, but has CreateAccessKeyResponse tag")
	}

	// Verify all required fields are present
	requiredFields := []string{
		"<AccessKeyId>",
		"</AccessKeyId>",
		"<SecretAccessKey>",
		"</SecretAccessKey>",
		"<UserName>",
		"</UserName>",
		"<Status>Active</Status>",
	}

	for _, field := range requiredFields {
		if !strings.Contains(body, field) {
			t.Errorf("CreateAccessKey() response missing required field: %s", field)
		}
	}
}
