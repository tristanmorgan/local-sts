package sts

import (
	"encoding/base64"
	"log"
	"net/http"
	"regexp"
	"text/template"
	"time"

	"github.com/google/uuid"
)

const sessionTokenXML = `<GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetSessionTokenResult>
    <Credentials>
      <AccessKeyId>{{ .AccessKey }}</AccessKeyId>
      <SessionToken>
       {{ .Token }}
      </SessionToken>
      <SecretAccessKey>{{ .SecretKey }}</SecretAccessKey>
      <Expiration>{{ .Expiration }}</Expiration>
    </Credentials>
  </GetSessionTokenResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestId }}</RequestId>
  </ResponseMetadata>
</GetSessionTokenResponse>`

// SessionTokenVars holds the template variables for STS SessionTokenVars API responses.
type SessionTokenVars struct {
	Token      string
	AccessKey  string
	SecretKey  string
	Expiration string
	RequestId  string
}

const AssumeRoleXML = `
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
  <SourceIdentity>{{ .UserStrng }}</SourceIdentity>
    <AssumedRoleUser>
	<Arn>arn:aws:sts::{{ .AccountID }}:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>{{ .AccessKey }}</AccessKeyId>
      <SecretAccessKey>{{ .SecretKey }}</SecretAccessKey>
      <SessionToken>
       {{ .Token }}
      </SessionToken>
      <Expiration>{{ .Expiration }}</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestId }}</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>
`

// AssumeRoleVars holds the template variables for STS AssumeRole API responses.
type AssumeRoleVars struct {
	UserStrng  string
	AccountID  string
	RoleId     string
	Token      string
	AccessKey  string
	SecretKey  string
	Expiration string
	RequestId  string
}

// GetSessionToken handles API calls to GetSessionToken
func GetSessionToken(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	// Extract accessKey from Authorization header
	accessKey := ""
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		// Use regex to extract access key from Credential=<ACCESS_KEY>/...
		re := regexp.MustCompile(`Credential=(AKIA[A-Z234567]{16})/`)
		matches := re.FindStringSubmatch(authHeader)
		if len(matches) > 1 {
			accessKey = matches[1]
		}
	}

	// ONE_HOUR < AssumeRole
	// TWELVE_HOUR < GetSessionToken
	// ONE_HOUR < GetFederationToken
	expiration := time.Now().Add(time.Hour * 12).Format("2006-01-02T15:04:05Z")

	data := []byte(accessKey + "0123456789")
	secretKey := base64.StdEncoding.EncodeToString(data)

	data = []byte(sessionTokenXML[:177])
	token := base64.StdEncoding.EncodeToString(data)

	respVar := SessionTokenVars{token, accessKey, secretKey, expiration, requestID}
	tmpl, err := template.New("resp").Parse(sessionTokenXML)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}

// AssumeRole handles API calls to AssumeRole
func AssumeRole(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	// Extract accessKey from Authorization header
	accessKey := ""
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		// Use regex to extract access key from Credential=<ACCESS_KEY>/...
		re := regexp.MustCompile(`Credential=(AKIA[A-Z234567]{16})/`)
		matches := re.FindStringSubmatch(authHeader)
		if len(matches) > 1 {
			accessKey = matches[1]
		}
	}

	accountID := decodeARN(accessKey)
	userStr := getFakeUser(accessKey)
	roleId := "AROA" + accessKey[4:]

	// ONE_HOUR < AssumeRole
	// TWELVE_HOUR < GetSessionToken
	// ONE_HOUR < GetFederationToken
	expiration := time.Now().Add(time.Hour).Format("2006-01-02T15:04:05Z")

	data := []byte(accessKey + "0123456789")
	secretKey := base64.StdEncoding.EncodeToString(data)

	data = []byte(sessionTokenXML[:177])
	token := base64.StdEncoding.EncodeToString(data)

	respVar := AssumeRoleVars{userStr, accountID, roleId, token, accessKey, secretKey, expiration, requestID}
	tmpl, err := template.New("resp").Parse(AssumeRoleXML)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
