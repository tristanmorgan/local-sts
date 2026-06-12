package main

import (
	"log"
	"net/http"
	"regexp"
	"text/template"

	"github.com/google/uuid"
)

const UserIDTemplate = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::{{ .AccountId }}:user/Alice</Arn>
    <UserId>{{ .AccessKey }}</UserId>
    <Account>{{ .AccountId }}</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestId }}</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>`

const keyInfoTemplate = `<GetAccessKeyInfoResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetAccessKeyInfoResult>
    <Account>{{ .AccountId }}</Account>
  </GetAccessKeyInfoResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestId }}</RequestId>
  </ResponseMetadata>
</GetAccessKeyInfoResponse>`

type ResponseVars struct {
	AccountId string
	AccessKey string
	RequestId string
}

func stsCall(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		req.ParseForm()
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
	request_id := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", request_id)
	w.Header().Set("Content-Type", "text/xml")

	// Extract access_key from Authorization header
	// Format: AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/sts/aws4_request,...
	access_key := ""
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		// Use regex to extract access key from Credential=<ACCESS_KEY>/...
		re := regexp.MustCompile(`Credential=([A-Z0-9]+)/`)
		matches := re.FindStringSubmatch(authHeader)
		if len(matches) > 1 {
			access_key = matches[1]
		}
	}
	account_id := decodeARN(access_key)

	respVar := ResponseVars{account_id, access_key, request_id}
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
	request_id := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", request_id)
	w.Header().Set("Content-Type", "text/xml")

	// Extract access_key from form parameter AccessKeyId
	access_key := req.FormValue("AccessKeyId")
	account_id := decodeARN(access_key)

	respVar := ResponseVars{account_id, access_key, request_id}
	tmpl, err := template.New("resp").Parse(keyInfoTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
