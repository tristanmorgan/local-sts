package sts

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetCallerIdentity(t *testing.T) {
	tests := []struct {
		name              string
		authHeader        string
		expectedARN       string
		expectedAccessKey string
		expectedAccountID string
		expectedStatus    int
	}{
		{
			name:              "Valid AWS4 Authorization with AKIAZOXKDENHR2JTNJLI",
			authHeader:        "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host;user-agent;x-amz-date, Signature=abcd",
			expectedARN:       "arn:aws:iam::650104742735:user/Ivan",
			expectedAccessKey: "AIDAZOXKDENHR2JTNJLI",
			expectedAccountID: "650104742735",
			expectedStatus:    http.StatusOK,
		},
		{
			name:              "Valid AWS4 Authorization with AKIASIFCFAPDEMQNV3SO",
			authHeader:        "AWS4-HMAC-SHA256 Credential=AKIASIFCFAPDEMQNV3SO/20160126/us-east-1/sts/aws4_request, SignedHeaders=host;user-agent;x-amz-date, Signature=1234",
			expectedARN:       "arn:aws:iam::154958889926:user/Peggy",
			expectedAccessKey: "AIDASIFCFAPDEMQNV3SO",
			expectedAccountID: "154958889926",
			expectedStatus:    http.StatusOK,
		},
		{
			name:              "Valid AWS4 Authorization with ASIADVUE6CL3HNEWV6SC",
			authHeader:        "AWS4-HMAC-SHA256 Credential=ASIADVUE6CL3HNEWV6SC/20160126/us-east-1/sts/aws4_request, SignedHeaders=host;user-agent;x-amz-date, Signature=WXYZ",
			expectedARN:       "arn:aws:sts::252608123638:assumed-role/role-name/Carol",
			expectedAccessKey: "AROADVUE6CL3HNEWV6SC",
			expectedAccountID: "252608123638",
			expectedStatus:    http.StatusOK,
		},
		{
			name:              "No Authorization header - uses default (invalid key)",
			authHeader:        "",
			expectedARN:       "arn:aws:iam::000000000000:user/Invalid",
			expectedAccessKey: "",
			expectedAccountID: "000000000000",
			expectedStatus:    http.StatusUnauthorized,
		},
		{
			name:              "Invalid Authorization header format - uses default",
			authHeader:        "Bearer some-token",
			expectedARN:       "arn:aws:iam::000000000000:user/Invalid",
			expectedAccessKey: "",
			expectedAccountID: "000000000000",
			expectedStatus:    http.StatusUnauthorized,
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
			GetCallerIdentity(rr, req, "requ-esti-duuid")

			// Check status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusUnauthorized {
				return
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

			if !strings.Contains(body, tt.expectedARN) {
				t.Errorf("response body does not contain ARN %q", tt.expectedARN)
			}
		})
	}
}

func TestGetCallerIdentityXMLStructure(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	rr := httptest.NewRecorder()
	GetCallerIdentity(rr, req, "requ-esti-duuid")

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

func TestGetAccessKeyInfo(t *testing.T) {
	tests := []struct {
		name              string
		accessKeyParam    string
		expectedAccessKey string
		expectedAccountID string
	}{
		{
			name:              "Valid AccessKeyId - AKIAZOXKDENHR2JTNJLI",
			accessKeyParam:    "AKIAZOXKDENHR2JTNJLI",
			expectedAccessKey: "AKIAZOXKDENHR2JTNJLI",
			expectedAccountID: "650104742735",
		},
		{
			name:              "Valid AccessKeyId - AKIASIFCFAPDEMQNV3SO",
			accessKeyParam:    "AKIASIFCFAPDEMQNV3SO",
			expectedAccessKey: "AKIASIFCFAPDEMQNV3SO",
			expectedAccountID: "154958889926",
		},
		{
			name:              "Valid AccessKeyId - AKIA5L7HQJMWG3EHBA3J",
			accessKeyParam:    "AKIA5L7HQJMWG3EHBA3J",
			expectedAccessKey: "AKIA5L7HQJMWG3EHBA3J",
			expectedAccountID: "919071640364",
		},
		{
			name:              "No AccessKeyId parameter - uses default",
			accessKeyParam:    "",
			expectedAccessKey: "AKIAI44QH8DHBEXAMPLE",
			expectedAccountID: "000000000000",
		},
		{
			name:              "Invalid AccessKeyId",
			accessKeyParam:    "AKIAI44QH8DHBEXAMPLE",
			expectedAccessKey: "AKIAI44QH8DHBEXAMPLE",
			expectedAccountID: "000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test request with form data
			formData := ""
			if tt.accessKeyParam != "" {
				formData = "AccessKeyId=" + tt.accessKeyParam
			}
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			GetAccessKeyInfo(rr, req, "requ-esti-duuid")

			// Check status code
			if status := rr.Code; status != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
			}

			// Check response body contains expected values
			body := rr.Body.String()

			// Check for account ID in response
			if !strings.Contains(body, tt.expectedAccountID) {
				t.Errorf("response body does not contain expected account ID %q, got: %s", tt.expectedAccountID, body)
			}

			// Check for XML structure
			if !strings.Contains(body, "<GetAccessKeyInfoResponse") {
				t.Error("response body does not contain GetAccessKeyInfoResponse element")
			}

			if !strings.Contains(body, "<GetAccessKeyInfoResult>") {
				t.Error("response body does not contain GetAccessKeyInfoResult element")
			}
		})
	}
}

func TestGetAccessKeyInfoXMLStructure(t *testing.T) {
	formData := "AccessKeyId=AKIAZOXKDENHR2JTNJLI"
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	GetAccessKeyInfo(rr, req, "requ-esti-duuid")

	body := rr.Body.String()

	// Check for required XML elements
	requiredElements := []string{
		"<GetAccessKeyInfoResponse",
		"<GetAccessKeyInfoResult>",
		"<Account>",
		"</GetAccessKeyInfoResult>",
		"<ResponseMetadata>",
		"<RequestId>",
		"</ResponseMetadata>",
		"</GetAccessKeyInfoResponse>",
	}

	for _, element := range requiredElements {
		if !strings.Contains(body, element) {
			t.Errorf("response body missing required XML element: %q", element)
		}
	}
}

func BenchmarkGetCallerIdentity(b *testing.B) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc")

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		GetCallerIdentity(rr, req, "requ-esti-duuid")
	}
}

func BenchmarkGetAccessKeyInfo(b *testing.B) {
	formData := "AccessKeyId=AKIAZOXKDENHR2JTNJLI"
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		GetAccessKeyInfo(rr, req, "requ-esti-duuid")
	}
}
