package sts

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestGetSessionToken(t *testing.T) {
	tests := []struct {
		name            string
		authHeader      string
		expectedPattern string
		expectedStatus  int
	}{
		{
			name:            "Valid Authorization header with AKIA key",
			authHeader:      "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedPattern: "ASIAZOXKDENHR",
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "Valid Authorization header with different AKIA key",
			authHeader:      "AWS4-HMAC-SHA256 Credential=AKIASIFCFAPDEMQNV3SO/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=xyz",
			expectedPattern: "ASIASIFCFAPDEM",
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "No Authorization header",
			authHeader:      "",
			expectedPattern: "",
			expectedStatus:  http.StatusUnauthorized,
		},
		{
			name:            "Invalid Authorization header format",
			authHeader:      "Bearer some-token",
			expectedPattern: "",
			expectedStatus:  http.StatusUnauthorized,
		},
		{
			name:            "Authorization header with ASIA key",
			authHeader:      "AWS4-HMAC-SHA256 Credential=ASIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedPattern: "",
			expectedStatus:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			GetSessionToken(rr, req)

			// Check status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusUnauthorized {
				return
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

			body := rr.Body.String()

			// Check for XML structure
			if !strings.Contains(body, "<GetSessionTokenResponse") {
				t.Error("response body does not contain GetSessionTokenResponse element")
			}

			// Check for expected access key pattern if provided
			if tt.expectedPattern != "" {
				if !strings.Contains(body, tt.expectedPattern) {
					t.Errorf("response body does not contain expected access key pattern %q", tt.expectedPattern)
				}
			}

			// Check for required elements
			requiredElements := []string{
				"<GetSessionTokenResult>",
				"<Credentials>",
				"<AccessKeyId>",
				"<SessionToken>",
				"<SecretAccessKey>",
				"<Expiration>",
				"</Credentials>",
				"</GetSessionTokenResult>",
				"<ResponseMetadata>",
				"<RequestId>",
				"</ResponseMetadata>",
			}

			for _, element := range requiredElements {
				if !strings.Contains(body, element) {
					t.Errorf("response body missing required XML element: %q", element)
				}
			}
		})
	}
}

func TestGetSessionTokenExpiration(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	rr := httptest.NewRecorder()

	beforeCall := time.Now()
	GetSessionToken(rr, req)
	afterCall := time.Now()

	body := rr.Body.String()

	// Extract expiration time from response
	expirationStart := strings.Index(body, "<Expiration>")
	expirationEnd := strings.Index(body, "</Expiration>")

	if expirationStart == -1 || expirationEnd == -1 {
		t.Fatal("Could not find Expiration element in response")
	}

	expirationStr := body[expirationStart+12 : expirationEnd]
	expiration, err := time.Parse("2006-01-02T15:04:05Z", expirationStr)
	if err != nil {
		t.Fatalf("Could not parse expiration time: %v", err)
	}

	// Check that expiration is approximately 12 hours from now
	expectedMin := beforeCall.Add(12 * time.Hour).Add(-1 * time.Minute)
	expectedMax := afterCall.Add(12 * time.Hour).Add(1 * time.Minute)

	if expiration.Before(expectedMin) || expiration.After(expectedMax) {
		t.Errorf("Expiration time %v is not within expected range [%v, %v]", expiration, expectedMin, expectedMax)
	}
}

func TestGetSessionTokenSecretKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	rr := httptest.NewRecorder()
	GetSessionToken(rr, req)

	body := rr.Body.String()

	// Check that SecretAccessKey is base64 encoded
	secretKeyStart := strings.Index(body, "<SecretAccessKey>")
	secretKeyEnd := strings.Index(body, "</SecretAccessKey>")

	if secretKeyStart == -1 || secretKeyEnd == -1 {
		t.Fatal("Could not find SecretAccessKey element in response")
	}

	secretKey := body[secretKeyStart+17 : secretKeyEnd]

	// Base64 encoded strings should only contain valid base64 characters
	validBase64 := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	if !validBase64.MatchString(secretKey) {
		t.Errorf("SecretAccessKey %q is not valid base64", secretKey)
	}
}

func TestAssumeRole(t *testing.T) {
	tests := []struct {
		name            string
		authHeader      string
		expectedPattern string
		expectedStatus  int
	}{
		{
			name:            "Valid Authorization header with AKIA key",
			authHeader:      "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedPattern: "ASIAZOXKDENHR",
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "Valid Authorization header with different AKIA key",
			authHeader:      "AWS4-HMAC-SHA256 Credential=AKIASIFCFAPDEMQNV3SO/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=xyz",
			expectedPattern: "ASIASIFCFAPDEM",
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "No Authorization header",
			authHeader:      "",
			expectedPattern: "",
			expectedStatus:  http.StatusUnauthorized,
		},
		{
			name:            "Invalid Authorization header format",
			authHeader:      "Bearer some-token",
			expectedPattern: "",
			expectedStatus:  http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			AssumeRole(rr, req)

			// Check status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusUnauthorized {
				return
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

			body := rr.Body.String()

			// Check for XML structure
			if !strings.Contains(body, "<AssumeRoleResponse") {
				t.Error("response body does not contain AssumeRoleResponse element")
			}

			// Check for expected access key pattern if provided
			if tt.expectedPattern != "" {
				if !strings.Contains(body, tt.expectedPattern) {
					t.Errorf("response body does not contain expected access key pattern %q", tt.expectedPattern)
				}
			}

			// Check for required elements
			requiredElements := []string{
				"<AssumeRoleResult>",
				"<SourceIdentity>",
				"<AssumedRoleUser>",
				"<Arn>",
				"<AssumedRoleId>",
				"</AssumedRoleUser>",
				"<Credentials>",
				"<AccessKeyId>",
				"<SecretAccessKey>",
				"<SessionToken>",
				"<Expiration>",
				"</Credentials>",
				"<PackedPolicySize>",
				"</AssumeRoleResult>",
				"<ResponseMetadata>",
				"<RequestId>",
				"</ResponseMetadata>",
			}

			for _, element := range requiredElements {
				if !strings.Contains(body, element) {
					t.Errorf("response body missing required XML element: %q", element)
				}
			}
		})
	}
}

func TestAssumeRoleExpiration(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	rr := httptest.NewRecorder()

	beforeCall := time.Now()
	AssumeRole(rr, req)
	afterCall := time.Now()

	body := rr.Body.String()

	// Extract expiration time from response
	expirationStart := strings.Index(body, "<Expiration>")
	expirationEnd := strings.Index(body, "</Expiration>")

	if expirationStart == -1 || expirationEnd == -1 {
		t.Fatal("Could not find Expiration element in response")
	}

	expirationStr := body[expirationStart+12 : expirationEnd]
	expiration, err := time.Parse("2006-01-02T15:04:05Z", expirationStr)
	if err != nil {
		t.Fatalf("Could not parse expiration time: %v", err)
	}

	// Check that expiration is approximately 1 hour from now (AssumeRole uses 1 hour)
	expectedMin := beforeCall.Add(1 * time.Hour).Add(-1 * time.Minute)
	expectedMax := afterCall.Add(1 * time.Hour).Add(1 * time.Minute)

	if expiration.Before(expectedMin) || expiration.After(expectedMax) {
		t.Errorf("Expiration time %v is not within expected range [%v, %v]", expiration, expectedMin, expectedMax)
	}
}

func TestAssumeRoleAccountID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	rr := httptest.NewRecorder()
	AssumeRole(rr, req)

	body := rr.Body.String()

	// Check that the account ID is decoded correctly
	expectedAccountID := "650104742735"
	if !strings.Contains(body, expectedAccountID) {
		t.Errorf("response body does not contain expected account ID %q", expectedAccountID)
	}

	// Check that the ARN contains the account ID
	expectedARN := "arn:aws:sts::" + expectedAccountID + ":assumed-role/demo/TestAR"
	if !strings.Contains(body, expectedARN) {
		t.Errorf("response body does not contain expected ARN %q", expectedARN)
	}
}

func TestAssumeRoleUserString(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+tt.accessKey+"/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

			rr := httptest.NewRecorder()
			AssumeRole(rr, req)

			body := rr.Body.String()

			// Check that the user string appears in SourceIdentity
			if !strings.Contains(body, "<SourceIdentity>"+tt.expectedUser+"</SourceIdentity>") {
				t.Errorf("response body does not contain expected user %q in SourceIdentity", tt.expectedUser)
			}
		})
	}
}

func TestGetFederationToken(t *testing.T) {
	tests := []struct {
		name            string
		authHeader      string
		expectedPattern string
		expectedStatus  int
	}{
		{
			name:            "Valid Authorization header with AKIA key",
			authHeader:      "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedPattern: "ASIAZOXKDENHR",
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "Valid Authorization header with different AKIA key",
			authHeader:      "AWS4-HMAC-SHA256 Credential=AKIASIFCFAPDEMQNV3SO/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=xyz",
			expectedPattern: "ASIASIFCFAPDEM",
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "No Authorization header",
			authHeader:      "",
			expectedPattern: "",
			expectedStatus:  http.StatusUnauthorized,
		},
		{
			name:            "Invalid Authorization header format",
			authHeader:      "Bearer some-token",
			expectedPattern: "",
			expectedStatus:  http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			GetFederationToken(rr, req)

			// Check status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusUnauthorized {
				return
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

			body := rr.Body.String()

			// Check for XML structure
			if !strings.Contains(body, "<GetFederationTokenResponse") {
				t.Error("response body does not contain GetFederationTokenResponse element")
			}

			// Check for expected access key pattern if provided
			if tt.expectedPattern != "" {
				if !strings.Contains(body, tt.expectedPattern) {
					t.Errorf("response body does not contain expected access key pattern %q", tt.expectedPattern)
				}
			}

			// Check for required elements
			requiredElements := []string{
				"<GetFederationTokenResult>",
				"<Credentials>",
				"<SecretAccessKey>",
				"<SessionToken>",
				"<Expiration>",
				"<AccessKeyId>",
				"</Credentials>",
				"<FederatedUser>",
				"<Arn>",
				"<FederatedUserId>",
				"</FederatedUser>",
				"<PackedPolicySize>",
				"</GetFederationTokenResult>",
				"<ResponseMetadata>",
				"<RequestId>",
				"</ResponseMetadata>",
			}

			for _, element := range requiredElements {
				if !strings.Contains(body, element) {
					t.Errorf("response body missing required XML element: %q", element)
				}
			}
		})
	}
}

func TestGetFederationTokenExpiration(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	rr := httptest.NewRecorder()

	beforeCall := time.Now()
	GetFederationToken(rr, req)
	afterCall := time.Now()

	body := rr.Body.String()

	// Extract expiration time from response
	expirationStart := strings.Index(body, "<Expiration>")
	expirationEnd := strings.Index(body, "</Expiration>")

	if expirationStart == -1 || expirationEnd == -1 {
		t.Fatal("Could not find Expiration element in response")
	}

	expirationStr := body[expirationStart+12 : expirationEnd]
	expiration, err := time.Parse("2006-01-02T15:04:05Z", expirationStr)
	if err != nil {
		t.Fatalf("Could not parse expiration time: %v", err)
	}

	// Check that expiration is approximately 1 hour from now (GetFederationToken uses 1 hour)
	expectedMin := beforeCall.Add(1 * time.Hour).Add(-1 * time.Minute)
	expectedMax := afterCall.Add(1 * time.Hour).Add(1 * time.Minute)

	if expiration.Before(expectedMin) || expiration.After(expectedMax) {
		t.Errorf("Expiration time %v is not within expected range [%v, %v]", expiration, expectedMin, expectedMax)
	}
}

func TestGetFederationTokenAccountID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	rr := httptest.NewRecorder()
	GetFederationToken(rr, req)

	body := rr.Body.String()

	// Check that the account ID is decoded correctly
	expectedAccountID := "650104742735"
	if !strings.Contains(body, expectedAccountID) {
		t.Errorf("response body does not contain expected account ID %q", expectedAccountID)
	}

	// Check that the ARN contains the account ID and user string
	expectedUser := "Ivan"
	expectedARN := "arn:aws:sts::" + expectedAccountID + ":federated-user/" + expectedUser
	if !strings.Contains(body, expectedARN) {
		t.Errorf("response body does not contain expected ARN %q", expectedARN)
	}

	// Check FederatedUserId format
	expectedFederatedUserID := expectedAccountID + ":" + expectedUser
	if !strings.Contains(body, expectedFederatedUserID) {
		t.Errorf("response body does not contain expected FederatedUserId %q", expectedFederatedUserID)
	}
}

func TestGetAuthorisation(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectedKey string
		expectError bool
	}{
		{
			name:        "Valid AWS4 Authorization with AKIA key",
			authHeader:  "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedKey: "AKIAZOXKDENHR2JTNJLI",
			expectError: false,
		},
		{
			name:        "Valid AWS4 Authorization with ASIA key",
			authHeader:  "AWS4-HMAC-SHA256 Credential=ASIASIFCFAPDEMQNV3SO/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=xyz",
			expectedKey: "ASIASIFCFAPDEMQNV3SO",
			expectError: false,
		},
		{
			name:        "No Authorization header",
			authHeader:  "",
			expectedKey: "",
			expectError: true,
		},
		{
			name:        "Invalid Authorization header format - Bearer token",
			authHeader:  "Bearer some-token",
			expectedKey: "",
			expectError: true,
		},
		{
			name:        "Invalid Authorization header format - malformed AWS4",
			authHeader:  "AWS4-HMAC-SHA256 Credential=INVALID/20160126/us-east-1/sts/aws4_request",
			expectedKey: "",
			expectError: true,
		},
		{
			name:        "Invalid Authorization header format - missing Credential",
			authHeader:  "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abc",
			expectedKey: "",
			expectError: true,
		},
		{
			name:        "Valid Authorization with extra spaces",
			authHeader:  "AWS4-HMAC-SHA256  Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request,  SignedHeaders=host,  Signature=abc",
			expectedKey: "AKIAZOXKDENHR2JTNJLI",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			accessKey, err := GetAuthorisation(req)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if accessKey != "" {
					t.Errorf("expected empty access key on error, got %q", accessKey)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if accessKey != tt.expectedKey {
					t.Errorf("expected access key %q, got %q", tt.expectedKey, accessKey)
				}
			}
		})
	}
}

func BenchmarkGetSessionToken(b *testing.B) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		GetSessionToken(rr, req)
	}
}

func BenchmarkAssumeRole(b *testing.B) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		AssumeRole(rr, req)
	}
}

func BenchmarkGetFederationToken(b *testing.B) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		GetFederationToken(rr, req)
	}
}
