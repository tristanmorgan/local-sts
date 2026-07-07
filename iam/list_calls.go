package iam

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"text/template"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tristanmorgan/local-sts/metrics"
)

func decodeARN(accessKeyID string) (decodeAccountID string) {
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

const listUsersTemplate = `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
 <ListUsersResult>
    <Users>
       <member>
          <UserId>{{ .AccessKey }}</UserId>
          <Path>/division_abc/subdivision_xyz/engineering/</Path>
          <UserName>{{ .UserStrng }}</UserName>
          <Arn>arn:aws:iam::{{ .AccountID }}:user/division_abc/subdivision_xyz/engineering/{{ .UserStrng }}</Arn>
          <CreateDate>2012-09-05T19:38:48Z</CreateDate>
          <PasswordLastUsed>2014-09-08T21:47:36Z</PasswordLastUsed>
       </member>
    </Users>
    <IsTruncated>false</IsTruncated>
 </ListUsersResult>
 <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
 </ResponseMetadata>
</ListUsersResponse>`

const listAccessKeysTemplate = `<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListAccessKeysResult>
    <UserName>{{ .UserStrng }}</UserName>
    <AccessKeyMetadata>
       <member>
          <UserName>{{ .UserStrng }}</UserName>
          <AccessKeyId>{{ .AccessKey }}</AccessKeyId>
          <Status>Active</Status>
	   <CreateDate>2016-12-03T18:53:41Z</CreateDate>
       </member>
    </AccessKeyMetadata>
    <IsTruncated>false</IsTruncated>
  </ListAccessKeysResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestID}}</RequestId>
  </ResponseMetadata>
</ListAccessKeysResponse>`

// ListUsersVars holds the template variables for IAM ListUsers API responses.
type ListUsersVars struct {
	AccountID string
	AccessKey string
	RequestID string
	UserStrng string
}

// ListAccessKeysVars holds the template variables for IAM ListAccessKeys API responses.
type ListAccessKeysVars struct {
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

// ListUsers handles API calls to ListUsers
func ListUsers(w http.ResponseWriter, req *http.Request) {
	// Action=ListUsers&Version=2011-06-15
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	// Extract accessKey from Authorization header
	// Format: AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/iam/aws4_request,...
	accessKey, err := GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	accountID := decodeARN(accessKey)
	userStr := getFakeUser(accessKey)
	if len(accessKey) > 4 {
		accessKey = "AIDI" + accessKey[4:]
	}

	respVar := ListUsersVars{accountID, accessKey, requestID, userStr}
	tmpl, err := template.New("resp").Parse(listUsersTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}

// ListAccessKeys handles API calls to ListAccessKeys
func ListAccessKeys(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	accessKey, err := GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userStr := getFakeUser(accessKey)

	respVar := ListAccessKeysVars{accessKey, requestID, userStr}
	tmpl, err := template.New("resp").Parse(listAccessKeysTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
