package main

import (
	"net/http"
	"net/http/httptest"
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

func BenchmarkDecodeARN(b *testing.B) {
	accessKey := "AKIAZOXKDENHR2JTNJLI"
	for i := 0; i < b.N; i++ {
		decodeARN(accessKey)
	}
}

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
