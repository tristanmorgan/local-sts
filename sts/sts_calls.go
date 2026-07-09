package sts

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tristanmorgan/local-sts/metrics"
)

// DecodeAID decodes the access key to extract Account ID.
func DecodeAID(accessKeyID string) (decodeAccountID string) {
	awsTable := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	// Extract characters 3-12 (10 characters)
	if match, err := regexp.Match("A[K,S]IA[A-Z234567]{16}", []byte(accessKeyID)); err != nil || !match {
		return "000000000000"
	}
	paddedNo := accessKeyID[3:13]

	// Base32 decode
	var decimal uint64 = 0
	for _, char := range paddedNo {
		index := bytes.IndexByte([]byte(awsTable), byte(char))
		decimal = (decimal << 5) + uint64(index)
	}

	// Shift right by 4 bits and mask with 40-bit mask
	mask := uint64((1 << 40) - 1)
	decimal = (decimal >> 4) & mask

	// Format as 12-digit string with leading zeros
	return fmt.Sprintf("%012d", decimal)
}

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
    <Arn>arn:aws:sts::{{ .AccountID }}:assumed-role/role-name/{{ .UserStrng }}</Arn>
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

const errorMessageTemplate = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidClientTokenId</Code>
    <Message>The security token included in the request is invalid.</Message>
  </Error>
  <RequestId>{{ .RequestID }}</RequestId>
</ErrorResponse>`

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

// GetFakeUser picks a "user" based on last digit of access key
func GetFakeUser(accessKey string) (name string) {
	if accessKey == "" {
		return "Invalid"
	}
	awsTable := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	bstr := []byte(accessKey)
	index := bytes.IndexByte([]byte(awsTable), byte(bstr[len(bstr)-1]))
	if index < 0 {
		return "Invalid"
	}
	index = index & 0x0f
	return UserNames[index]
}

var errPermissionDenied = errors.New("permission denied")

// GetAuthorisation extracts the access key from the Authorization headers.
func GetAuthorisation(req *http.Request) (accessKey string, err error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		// Use regex to extract access key from Credential=<ACCESS_KEY>/...
		re := regexp.MustCompile(`Credential=(A[K,S]IA[A-Z234567]{16})/`)
		matches := re.FindStringSubmatch(authHeader)
		if len(matches) > 1 {
			return matches[1], nil
		}
	}
	return "", errPermissionDenied
}

// UnauthorizedResponse returns a foratted response to unauthorised calls.
func UnauthorizedResponse(requestID string, w http.ResponseWriter) {
	respVar := CallerIDVars{"", "", requestID, ""}
	tmpl, err := template.New("resp").Parse(errorMessageTemplate)
	if err != nil {
		panic(err)
	}
	b := new(strings.Builder)
	tmpl.Execute(b, respVar)
	http.Error(w, b.String(), http.StatusUnauthorized)
}

// GetCallerIdentity handles API calls to GetCallerIdentity
func GetCallerIdentity(w http.ResponseWriter, req *http.Request) {
	// Action=GetCallerIdentity&Version=2011-06-15
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

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
func GetAccessKeyInfo(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

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
