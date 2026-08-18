package sts

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"text/template"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tristanmorgan/local-sts/metrics"
)

const userIDTemplate = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::{{ .AccountID }}:user/{{ .UserStrng }}</Arn>
    <UserId>{{ .AccessKey }}</UserId>
    <Account>{{ .AccountID }}</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>`

const roleIDTemplate = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::{{ .AccountID }}:assumed-role/S3Access/{{ .UserStrng }}</Arn>
    <UserId>{{ .AccessKey }}:{{ .UserStrng }}</UserId>
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

// CallerIDVars holds the template variables for STS GetCallerIdentity API responses.
type CallerIDVars struct {
	AccountID string
	AccessKey string
	RequestID string
	UserStrng string
}

// KeyInfoVars holds the template variables for STS GetAccessKeyInfo API responses.
type KeyInfoVars struct {
	AccountID string
	RequestID string
}

var errPermissionDenied = errors.New("permission denied")

// GetCallerIdentity handles API calls to GetCallerIdentity
func GetCallerIdentity(w http.ResponseWriter, req *http.Request, requestID string) {
	// Extract accessKey from Authorization header
	// Format: AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/sts/aws4_request,...
	accessKey, err := GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		UnauthorizedResponse(requestID, w)
		return
	}
	accountID := DecodeAID(accessKey)
	userStr := GetFakeUser(accessKey)
	templateStr := userIDTemplate

	if strings.HasPrefix(accessKey, "ASIA") {
		accessKey = "AROA" + accessKey[4:]
		templateStr = roleIDTemplate
	} else {
		accessKey = "AIDA" + accessKey[4:]
	}

	respVar := CallerIDVars{accountID, accessKey, requestID, userStr}
	tmpl, err := template.New("resp").Parse(templateStr)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}

// GetAccessKeyInfo handles API calls to GetAccessKeyInfo
func GetAccessKeyInfo(w http.ResponseWriter, req *http.Request, requestID string) {
	w.Header().Set("x-amzn-RequestId", requestID)
	// Extract accessKey from form parameter AccessKeyId
	accessKey := req.FormValue("AccessKeyId")
	accountID := DecodeAID(accessKey)

	respVar := KeyInfoVars{accountID, requestID}
	tmpl, err := template.New("resp").Parse(keyInfoTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
