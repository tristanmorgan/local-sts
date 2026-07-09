package iam

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetUser(t *testing.T) {
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
				"<GetUserResponse",
				"<UserId>AIDAIOSFODNN7EXAMPLE</UserId>",
				"<UserName>",
				"<Arn>arn:aws:iam::",
				"<Path>/division_abc/subdivision_xyz/engineering/</Path>",
				"<CreateDate>2012-09-05T19:38:48Z</CreateDate>",
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
			req := httptest.NewRequest(http.MethodPost, "/?Action=GetUser&Version=2011-06-15", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			GetUser(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("GetUser() status = %v, want %v", w.Code, tt.wantStatus)
			}

			body := w.Body.String()
			for _, want := range tt.wantContains {
				if !contains(body, want) {
					t.Errorf("GetUser() body should contain %q, got %q", want, body)
				}
			}

			// Check headers for successful requests
			if tt.wantStatus == http.StatusOK {
				if contentType := w.Header().Get("Content-Type"); contentType != "text/xml" {
					t.Errorf("GetUser() Content-Type = %v, want text/xml", contentType)
				}
				if requestID := w.Header().Get("x-amzn-RequestId"); requestID == "" {
					t.Errorf("GetUser() missing x-amzn-RequestId header")
				}
			}
		})
	}
}

func TestGetRole(t *testing.T) {
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
				"<GetRoleResponse",
				"<RoleId>AROAIOSFODNN7EXAMPLE</RoleId>",
				"<RoleName>S3Access</RoleName>",
				"<Arn>arn:aws:iam::",
				"<Path>/application_abc/component_xyz/</Path>",
				"<AssumeRolePolicyDocument>",
				"<CreateDate>2012-05-08T23:34:01Z</CreateDate>",
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
			authHeader: "Basic dXNlcjpwYXNz",
			wantStatus: http.StatusUnauthorized,
			wantContains: []string{
				"<ErrorResponse",
				"<Code>InvalidClientTokenId",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/?Action=GetRole&Version=2011-06-15", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			GetRole(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("GetRole() status = %v, want %v", w.Code, tt.wantStatus)
			}

			body := w.Body.String()
			for _, want := range tt.wantContains {
				if !contains(body, want) {
					t.Errorf("GetRole() body should contain %q, got %q", want, body)
				}
			}

			// Check headers for successful requests
			if tt.wantStatus == http.StatusOK {
				if contentType := w.Header().Get("Content-Type"); contentType != "text/xml" {
					t.Errorf("GetRole() Content-Type = %v, want text/xml", contentType)
				}
				if requestID := w.Header().Get("x-amzn-RequestId"); requestID == "" {
					t.Errorf("GetRole() missing x-amzn-RequestId header")
				}
			}
		})
	}
}

func TestGetUserVarsTemplate(t *testing.T) {
	// Test that the template variables are correctly used
	req := httptest.NewRequest(http.MethodPost, "/?Action=GetUser&Version=2011-06-15", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...")

	w := httptest.NewRecorder()
	GetUser(w, req)

	body := w.Body.String()

	// Verify the response contains expected values
	expectedValues := []string{
		"581039954779",
		"AIDAIOSFODNN7EXAMPLE",
	}

	for _, expected := range expectedValues {
		if !contains(body, expected) {
			t.Errorf("GetUser() response should contain %q", expected)
		}
	}
}

func TestGetRoleVarsTemplate(t *testing.T) {
	// Test that the template variables are correctly used
	req := httptest.NewRequest(http.MethodPost, "/?Action=GetRole&Version=2011-06-15", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...")

	w := httptest.NewRecorder()
	GetRole(w, req)

	body := w.Body.String()

	// Verify the response contains expected values
	expectedValues := []string{
		"581039954779",
		"AROAIOSFODNN7EXAMPLE",
	}

	for _, expected := range expectedValues {
		if !contains(body, expected) {
			t.Errorf("GetRole() response should contain %q", expected)
		}
	}
}
