package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeARN(t *testing.T) {
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
			result := decodeARN(tt.accessKey)
			if result != tt.expectedID {
				t.Errorf("decodeARN(%q) = %q, want %q", tt.accessKey, result, tt.expectedID)
			}
		})
	}
}

func TestSTSCall(t *testing.T) {
	tests := []struct {
		name              string
		authHeader        string
		expectedAccessKey string
		expectedAccountID string
	}{
		{
			name:              "Valid AWS4 Authorization with AKIAZOXKDENHR2JTNJLI",
			authHeader:        "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host;user-agent;x-amz-date, Signature=abcd",
			expectedAccessKey: "AKIAZOXKDENHR2JTNJLI",
			expectedAccountID: "650104742735",
		},
		{
			name:              "Valid AWS4 Authorization with AKIASIFCFAPDEMQNV3SO",
			authHeader:        "AWS4-HMAC-SHA256 Credential=AKIASIFCFAPDEMQNV3SO/20160126/us-east-1/sts/aws4_request, SignedHeaders=host;user-agent;x-amz-date, Signature=1234",
			expectedAccessKey: "AKIASIFCFAPDEMQNV3SO",
			expectedAccountID: "154958889926",
		},
		{
			name:              "No Authorization header - uses default (invalid key)",
			authHeader:        "",
			expectedAccessKey: "AKIAI44QH8DHBEXAMPLE",
			expectedAccountID: "000000000000",
		},
		{
			name:              "Invalid Authorization header format - uses default",
			authHeader:        "Bearer some-token",
			expectedAccessKey: "AKIAI44QH8DHBEXAMPLE",
			expectedAccountID: "000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test request
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			stsCall(rr, req)

			// Check status code
			if status := rr.Code; status != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
			}

			// Check Content-Type header
			contentType := rr.Header().Get("Content-Type")
			if contentType != "text/xml" {
				t.Errorf("handler returned wrong content type: got %v want %v", contentType, "text/xml")
			}

			// Check x-amzn-RequestId header exists
			requestID := rr.Header().Get("x-amzn-RequestId")
			if requestID == "" {
				t.Error("handler did not set x-amzn-RequestId header")
			}

			// Check response body contains expected values
			body := rr.Body.String()

			// Check for access key in response
			if !strings.Contains(body, tt.expectedAccessKey) {
				t.Errorf("response body does not contain expected access key %q", tt.expectedAccessKey)
			}

			// Check for account ID in response
			if !strings.Contains(body, tt.expectedAccountID) {
				t.Errorf("response body does not contain expected account ID %q", tt.expectedAccountID)
			}

			// Check for XML structure
			if !strings.Contains(body, "<GetCallerIdentityResponse") {
				t.Error("response body does not contain GetCallerIdentityResponse element")
			}

			if !strings.Contains(body, "<Arn>arn:aws:iam::") {
				t.Error("response body does not contain ARN element")
			}
		})
	}
}

func TestSTSCallXMLStructure(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	rr := httptest.NewRecorder()
	stsCall(rr, req)

	body := rr.Body.String()

	// Check for required XML elements
	requiredElements := []string{
		"<GetCallerIdentityResponse",
		"<GetCallerIdentityResult>",
		"<Arn>",
		"<UserId>",
		"<Account>",
		"</GetCallerIdentityResult>",
		"<ResponseMetadata>",
		"<RequestId>",
		"</ResponseMetadata>",
		"</GetCallerIdentityResponse>",
	}

	for _, element := range requiredElements {
		if !strings.Contains(body, element) {
			t.Errorf("response body missing required XML element: %q", element)
		}
	}
}

func BenchmarkDecodeARN(b *testing.B) {
	accessKey := "AKIAZOXKDENHR2JTNJLI"
	for i := 0; i < b.N; i++ {
		decodeARN(accessKey)
	}
}

func BenchmarkSTSCall(b *testing.B) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		stsCall(rr, req)
	}
}
