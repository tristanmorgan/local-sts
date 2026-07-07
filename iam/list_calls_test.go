package iam

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDecodeARN(t *testing.T) {
	tests := []struct {
		name        string
		accessKeyID string
		want        string
	}{
		{
			name:        "Valid AKIA key",
			accessKeyID: "AKIAIOSFODNN7EXAMPLE",
			want:        "581039954779",
		},
		{
			name:        "Valid ASIA key",
			accessKeyID: "ASIAIOSFODNN7EXAMPLE",
			want:        "581039954779",
		},
		{
			name:        "Invalid key format",
			accessKeyID: "INVALID",
			want:        "000000000000",
		},
		{
			name:        "Empty key",
			accessKeyID: "",
			want:        "000000000000",
		},
		{
			name:        "Short key",
			accessKeyID: "AKIA",
			want:        "000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeARN(tt.accessKeyID)
			if got != tt.want {
				t.Errorf("decodeARN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetFakeUser(t *testing.T) {
	tests := []struct {
		name      string
		accessKey string
		want      string
	}{
		{
			name:      "Empty access key",
			accessKey: "",
			want:      "Invalid",
		},
		{
			name:      "Access key ending with A",
			accessKey: "AKIAIOSFODNN7EXAMPLA",
			want:      "Alice",
		},
		{
			name:      "Access key ending with B",
			accessKey: "AKIAIOSFODNN7EXAMPLB",
			want:      "Bob",
		},
		{
			name:      "Access key ending with 2",
			accessKey: "AKIAIOSFODNN7EXAMPL2",
			want:      "Mallory",
		},
		{
			name:      "Invalid character",
			accessKey: "AKIAIOSFODNN7EXAMPL!",
			want:      "Invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFakeUser(tt.accessKey)
			if got != tt.want {
				t.Errorf("getFakeUser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAuthorisation(t *testing.T) {
	tests := []struct {
		name      string
		authValue string
		wantKey   string
		wantErr   bool
	}{
		{
			name:      "Valid AWS4 signature",
			authValue: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...",
			wantKey:   "AKIAIOSFODNN7EXAMPLE",
			wantErr:   false,
		},
		{
			name:      "Valid ASIA key",
			authValue: "AWS4-HMAC-SHA256 Credential=ASIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...",
			wantKey:   "ASIAIOSFODNN7EXAMPLE",
			wantErr:   false,
		},
		{
			name:      "Missing Authorization header",
			authValue: "",
			wantKey:   "",
			wantErr:   true,
		},
		{
			name:      "Invalid format",
			authValue: "Bearer token123",
			wantKey:   "",
			wantErr:   true,
		},
		{
			name:      "Malformed credential",
			authValue: "AWS4-HMAC-SHA256 Credential=INVALID/20160126/us-east-1/iam/aws4_request",
			wantKey:   "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.authValue != "" {
				req.Header.Set("Authorization", tt.authValue)
			}

			gotKey, err := GetAuthorisation(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAuthorisation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotKey != tt.wantKey {
				t.Errorf("GetAuthorisation() = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}

func TestListUsers(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		wantStatus     int
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:       "Valid request",
			authHeader: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20160126/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=...",
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<ListUsersResponse",
				"<UserId>AIDIIOSFODNN7EXAMPLE</UserId>",
				"<UserName>",
				"<Arn>arn:aws:iam::",
			},
		},
		{
			name:       "Missing authorization",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantContains: []string{
				"Unauthorized",
			},
		},
		{
			name:       "Invalid authorization",
			authHeader: "Bearer invalid",
			wantStatus: http.StatusUnauthorized,
			wantContains: []string{
				"Unauthorized",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/?Action=ListUsers&Version=2011-06-15", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			ListUsers(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("ListUsers() status = %v, want %v", w.Code, tt.wantStatus)
			}

			body := w.Body.String()
			for _, want := range tt.wantContains {
				if !contains(body, want) {
					t.Errorf("ListUsers() body should contain %q, got %q", want, body)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if contains(body, notWant) {
					t.Errorf("ListUsers() body should not contain %q, got %q", notWant, body)
				}
			}
		})
	}
}

func TestListAccessKeys(t *testing.T) {
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
				"<ListAccessKeysResponse",
				"<AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>",
				"<Status>Active</Status>",
				"<UserName>",
			},
		},
		{
			name:       "Missing authorization",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantContains: []string{
				"Unauthorized",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/?Action=ListAccessKeys&Version=2011-06-15", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			ListAccessKeys(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("ListAccessKeys() status = %v, want %v", w.Code, tt.wantStatus)
			}

			body := w.Body.String()
			for _, want := range tt.wantContains {
				if !contains(body, want) {
					t.Errorf("ListAccessKeys() body should contain %q, got %q", want, body)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
