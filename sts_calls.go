package main

import (
	"bytes"
	"log"
	"net/http"
	"regexp"
	"text/template"

	"github.com/google/uuid"
)

// UserNames contains a list of common cryptographic protocol participant names.
var UserNames = [...]string{
	"Alice",
	"Bob",
	"Carol",
	"Dave",
	"Eve",
	"Frank",
	"Grace",
	"Heidi",
	"Ivan",
	"Judy",
	"Mallory",
	"Oscar",
	"Trent",
	"Walter",
	"Peggy",
	"Victor",
}

// UserIDTemplate is the XML template for GetCallerIdentity responses.
const UserIDTemplate = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::{{ .AccountID }}:user/{{ .UserStrng }}</Arn>
    <UserId>{{ .AccessKey }}</UserId>
    <Account>{{ .AccountID }}</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>`

const keyInfoTemplate = `<GetAccessKeyInfoResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetAccessKeyInfoResult>
    <Account>{{ .AccountID }}</Account>
  </GetAccessKeyInfoResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
  </ResponseMetadata>
</GetAccessKeyInfoResponse>`

// ResponseVars holds the template variables for STS API responses.
type ResponseVars struct {
	AccountID string
	AccessKey string
	RequestID string
	UserStrng string
}

func getFakeUser(accessKey string) (name string) {
	if accessKey == "" {
		return "Invalid"
	}
	awsTable := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	bstr := []byte(accessKey)
	index := bytes.IndexByte([]byte(awsTable), byte(bstr[len(bstr)-1]))
	if index > 16 {
		index -= 16
	} else if index < 0 {
		return "Invalid"
	}
	return UserNames[index]
}

func stsCall(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		err := req.ParseForm()
		if err != nil {
			http.Error(w, "Form Validadtion Error", http.StatusBadRequest)
		}
		action := req.FormValue("Action")
		switch action {
		case "GetCallerIdentity":
			stsCallerIdentityCall(w, req)
		case "GetAccessKeyInfo":
			stsKeyInfoCall(w, req)
		default:
			http.Error(w, "Action Not Allowed", http.StatusBadRequest)
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func stsCallerIdentityCall(w http.ResponseWriter, req *http.Request) {
	// Action=GetCallerIdentity&Version=2011-06-15
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	// Extract accessKey from Authorization header
	// Format: AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/sts/aws4_request,...
	accessKey := ""
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		// Use regex to extract access key from Credential=<ACCESS_KEY>/...
		re := regexp.MustCompile(`Credential=([A-Z0-9]+)/`)
		matches := re.FindStringSubmatch(authHeader)
		if len(matches) > 1 {
			accessKey = matches[1]
		}
	}
	accountID := decodeARN(accessKey)
	userStr := getFakeUser(accessKey)

	respVar := ResponseVars{accountID, accessKey, requestID, userStr}
	tmpl, err := template.New("resp").Parse(UserIDTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}

func stsKeyInfoCall(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	// Extract accessKey from form parameter AccessKeyId
	accessKey := req.FormValue("AccessKeyId")
	accountID := decodeARN(accessKey)

	respVar := ResponseVars{accountID, accessKey, requestID, "user"}
	tmpl, err := template.New("resp").Parse(keyInfoTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
