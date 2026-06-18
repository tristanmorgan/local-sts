package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	health(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check Server header
	serverHeader := rr.Header().Get("Server")
	expectedServer := "local-sts/" + Version + " (+" + Homepage + ")"
	if serverHeader != expectedServer {
		t.Errorf("handler returned wrong Server header: got %v want %v", serverHeader, expectedServer)
	}

	// Check response body
	body := rr.Body.String()
	expectedBody := "Healthy.\n"
	if body != expectedBody {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expectedBody)
	}
}

func TestSTSCall(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		url            string
		formData       string
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "POST routes to GetCallerIdentity",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetCallerIdentity",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetCallerIdentityResponse",
		},
		{
			name:           "POST routes to GetAccessKeyInfo",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetAccessKeyInfo&AccessKeyId=AKIAZOXKDENHR2JTNJLI",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetAccessKeyInfoResponse",
		},
		{
			name:           "POST routes to GetSessionToken",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetSessionToken",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetSessionTokenResponse",
		},
		{
			name:           "POST routes to GetFederationToken",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetFederationToken",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetFederationTokenResponse",
		},
		{
			name:           "POST routes to AssumeRole",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=AssumeRole",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<AssumeRoleResponse",
		},
		{
			name:           "POST with unknown action returns Bad Request",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=UnknownAction",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Action Not Allowed",
		},
		{
			name:           "POST with no action returns Bad Request",
			method:         http.MethodPost,
			url:            "/",
			formData:       "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Action Not Allowed",
		},
		{
			name:           "GET returns Method Not Allowed",
			method:         http.MethodGet,
			url:            "/",
			formData:       "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method Not Allowed",
		},
		{
			name:           "PUT returns Method Not Allowed",
			method:         http.MethodPut,
			url:            "/",
			formData:       "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method Not Allowed",
		},
		{
			name:           "DELETE returns Method Not Allowed",
			method:         http.MethodDelete,
			url:            "/",
			formData:       "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method Not Allowed",
		},
		{
			name:           "PATCH returns Method Not Allowed",
			method:         http.MethodPatch,
			url:            "/",
			formData:       "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method Not Allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.formData != "" {
				req = httptest.NewRequest(tt.method, tt.url, strings.NewReader(tt.formData))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, tt.url, nil)
			}
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			stsCall(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			body := rr.Body.String()
			if !strings.Contains(body, tt.expectedBody) {
				t.Errorf("response body does not contain expected content %q, got: %s", tt.expectedBody, body)
			}
		})
	}
}
