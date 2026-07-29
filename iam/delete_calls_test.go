package iam

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeleteAction(t *testing.T) {
	tests := []struct {
		name         string
		action       string
		wantContains []string
	}{
		{
			name:   "DeleteAccessKey response",
			action: "DeleteAccessKey",
			wantContains: []string{
				`<DeleteAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">`,
				"<ResponseMetadata>",
				"<RequestId>",
				"</DeleteAccessKeyResponse>",
			},
		},
		{
			name:   "DeleteUser response",
			action: "DeleteUser",
			wantContains: []string{
				`<DeleteUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">`,
				"<ResponseMetadata>",
				"<RequestId>",
				"</DeleteUserResponse>",
			},
		},
		{
			name:   "DeleteRole response",
			action: "DeleteRole",
			wantContains: []string{
				`<DeleteRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">`,
				"<ResponseMetadata>",
				"<RequestId>",
				"</DeleteRoleResponse>",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/?Action="+tt.action+"&Version=2010-05-08", nil)
			w := httptest.NewRecorder()

			DeleteAction(w, req, tt.action, "requ-esti-duuid")

			if w.Code != http.StatusOK {
				t.Fatalf("DeleteAction() status = %v, want %v", w.Code, http.StatusOK)
			}

			body := w.Body.String()
			for _, want := range tt.wantContains {
				if !strings.Contains(body, want) {
					t.Errorf("DeleteAction() body should contain %q, got %q", want, body)
				}
			}
		})
	}
}
