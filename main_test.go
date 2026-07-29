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
			formData:       "Action=GetCallerIdentity&Version=2011-06-15",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetCallerIdentityResponse",
		},
		{
			name:           "POST routes to GetAccessKeyInfo",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetAccessKeyInfo&AccessKeyId=AKIAZOXKDENHR2JTNJLI&Version=2011-06-15",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetAccessKeyInfoResponse",
		},
		{
			name:           "POST routes to GetSessionToken",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetSessionToken&Version=2011-06-15&DurationSeconds=3600",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetSessionTokenResponse",
		},
		{
			name:           "POST routes to GetFederationToken",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetFederationToken&Version=2011-06-15",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetFederationTokenResponse",
		},
		{
			name:           "POST routes to AssumeRole",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=AssumeRole&Version=2011-06-15",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<AssumeRoleResponse",
		},
		{
			name:           "POST routes to GetUser",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetUser&Version=2010-05-08",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetUserResponse",
		},
		{
			name:           "POST routes to GetRole",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=GetRole&Version=2010-05-08",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetRoleResponse",
		},
		{
			name:           "POST routes to ListUsers",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=ListUsers&Version=2010-05-08",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<ListUsersResponse",
		},
		{
			name:           "POST routes to ListAccessKeys",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=ListAccessKeys&Version=2010-05-08",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<ListAccessKeysResponse",
		},
		{
			name:           "POST routes to ListRoles",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=ListRoles&Version=2010-05-08",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<ListRolesResponse",
		},
		{
			name:           "POST routes to DeleteAccessKey",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=DeleteAccessKey&Version=2010-05-08",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<DeleteAccessKeyResponse",
		},
		{
			name:           "POST routes to DeleteUser",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=DeleteUser&Version=2010-05-08",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<DeleteUserResponse",
		},
		{
			name:           "POST routes to DeleteRole",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=DeleteRole&Version=2010-05-08",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<DeleteRoleResponse",
		},
		{
			name:           "POST with unknown action returns Bad Request",
			method:         http.MethodPost,
			url:            "/",
			formData:       "Action=UnknownAction&Version=2026-01-01",
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

			if tt.expectedStatus == http.StatusOK {
				if contentType := rr.Header().Get("Content-Type"); contentType != "text/xml" {
					t.Errorf("CreateAccessKey() Content-Type = %v, want text/xml", contentType)
				}
				if requestID := rr.Header().Get("x-amzn-RequestId"); requestID == "" {
					t.Errorf("CreateAccessKey() missing x-amzn-RequestId header")
				}
			}
		})
	}
}

func TestSTSCallWithModeRestrictions(t *testing.T) {
	tests := []struct {
		name           string
		stsOnly        bool
		iamOnly        bool
		action         string
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "STS-only mode allows STS actions",
			stsOnly:        true,
			iamOnly:        false,
			action:         "GetCallerIdentity",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetCallerIdentityResponse",
		},
		{
			name:           "STS-only mode rejects IAM actions",
			stsOnly:        true,
			iamOnly:        false,
			action:         "GetUser",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Action Not Allowed",
		},
		{
			name:           "IAM-only mode allows IAM actions",
			stsOnly:        false,
			iamOnly:        true,
			action:         "GetUser",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetUserResponse",
		},
		{
			name:           "IAM-only mode rejects STS actions",
			stsOnly:        false,
			iamOnly:        true,
			action:         "GetCallerIdentity",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Action Not Allowed",
		},
		{
			name:           "No mode restriction allows all STS actions",
			stsOnly:        false,
			iamOnly:        false,
			action:         "GetSessionToken",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<GetSessionTokenResponse",
		},
		{
			name:           "No mode restriction allows all IAM actions",
			stsOnly:        false,
			iamOnly:        false,
			action:         "ListUsers",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<ListUsersResponse",
		},
		{
			name:           "IAM-only mode allows delete IAM actions",
			stsOnly:        false,
			iamOnly:        true,
			action:         "DeleteUser",
			authHeader:     "AWS4-HMAC-SHA256 Credential=AKIAZOXKDENHR2JTNJLI/20160126/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=abc",
			expectedStatus: http.StatusOK,
			expectedBody:   "<DeleteUserResponse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set mode flags
			oldStsOnly := *stsOnly
			oldIamOnly := *iamOnly
			*stsOnly = tt.stsOnly
			*iamOnly = tt.iamOnly
			defer func() {
				*stsOnly = oldStsOnly
				*iamOnly = oldIamOnly
			}()

			formData := "Action=" + tt.action
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
