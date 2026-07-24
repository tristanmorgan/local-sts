package sts

import (
	"encoding/base64"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tristanmorgan/local-sts/metrics"
)

const sessionTokenXML = `<GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetSessionTokenResult>
    <Credentials>
      <AccessKeyId>{{ .AccessKey }}</AccessKeyId>
      <SessionToken>{{ .Token }}</SessionToken>
      <SecretAccessKey>{{ .SecretKey }}</SecretAccessKey>
      <Expiration>{{ .Expiration }}</Expiration>
    </Credentials>
  </GetSessionTokenResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
  </ResponseMetadata>
</GetSessionTokenResponse>`

// SessionTokenVars holds the template variables for STS SessionTokenVars API responses.
type SessionTokenVars struct {
	AccessKey  string
	SecretKey  string
	Token      string
	Expiration string
	RequestID  string
}

const assumeRoleXML = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <SourceIdentity>{{ .UserStrng }}</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::{{ .AccountID }}:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>{{ .RoleID }}:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>{{ .AccessKey }}</AccessKeyId>
      <SecretAccessKey>{{ .SecretKey }}</SecretAccessKey>
      <SessionToken>{{ .Token }}</SessionToken>
      <Expiration>{{ .Expiration }}</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>`

// AssumeRoleVars holds the template variables for STS AssumeRole API responses.
type AssumeRoleVars struct {
	UserStrng  string
	RoleID     string
	AccessKey  string
	SecretKey  string
	Token      string
	AccountID  string
	Expiration string
	RequestID  string
}

const getFederationTokenXML = `<GetFederationTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetFederationTokenResult>
    <Credentials>
      <SecretAccessKey>{{ .SecretKey }}</SecretAccessKey>
      <SessionToken>{{ .Token }}</SessionToken>
      <Expiration>{{ .Expiration }}</Expiration>
      <AccessKeyId>{{ .AccessKey }}</AccessKeyId>
    </Credentials>
    <FederatedUser>
      <Arn>arn:aws:sts::{{ .AccountID }}:federated-user/{{ .UserStrng }}</Arn>
      <FederatedUserId>{{ .AccountID }}:{{ .UserStrng }}</FederatedUserId>
    </FederatedUser>
    <PackedPolicySize>6</PackedPolicySize>
  </GetFederationTokenResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
  </ResponseMetadata>
</GetFederationTokenResponse>`

// GetFederationTokenVars holds the template variables for STS GetFederationToken API responses.
type GetFederationTokenVars struct {
	UserStrng  string
	AccessKey  string
	SecretKey  string
	Token      string
	AccountID  string
	Expiration string
	RequestID  string
}

// GetSessionToken handles API calls to GetSessionToken
func GetSessionToken(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	// Extract accessKey from Authorization header
	accessKey, err := GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		UnauthorizedResponse(requestID, w)
		return
	}
	accessKey = CreateNewKey(accessKey)
	accessKey = "ASIA" + accessKey[4:]

	// ONE_HOUR < AssumeRole
	// TWELVE_HOUR < GetSessionToken
	// ONE_HOUR < GetFederationToken
	expiration := time.Now().Add(time.Hour * 12).Format("2006-01-02T15:04:05Z")

	data := []byte(accessKey + "0123456789")
	secretKey := base64.StdEncoding.EncodeToString(data)

	data = []byte(sessionTokenXML[:177])
	token := base64.StdEncoding.EncodeToString(data)

	respVar := SessionTokenVars{accessKey, secretKey, token, expiration, requestID}
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
	accessKey, err := GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		UnauthorizedResponse(requestID, w)
		return
	}
	accessKey = CreateNewKey(accessKey)
	accessKey = "ASIA" + accessKey[4:]

	accountID := DecodeAID(accessKey)
	userStrng := GetFakeUser(accessKey)
	roleID := ""
	if len(accessKey) > 4 {
		roleID = "AROA" + accessKey[4:]
	}

	// ONE_HOUR < AssumeRole
	// TWELVE_HOUR < GetSessionToken
	// ONE_HOUR < GetFederationToken
	expiration := time.Now().Add(time.Hour).Format("2006-01-02T15:04:05Z")

	data := []byte(accessKey + "0123456789")
	secretKey := base64.StdEncoding.EncodeToString(data)

	data = []byte(sessionTokenXML[:177])
	token := base64.StdEncoding.EncodeToString(data)

	respVar := AssumeRoleVars{userStrng, roleID, accessKey, secretKey, token, accountID, expiration, requestID}
	tmpl, err := template.New("resp").Parse(assumeRoleXML)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}

// GetFederationToken handles API calls to GetFederationToken
func GetFederationToken(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	// Extract accessKey from Authorization header
	accessKey, err := GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		UnauthorizedResponse(requestID, w)
		return
	}
	accessKey = CreateNewKey(accessKey)
	accessKey = "ASIA" + accessKey[4:]

	accountID := DecodeAID(accessKey)
	userStrng := GetFakeUser(accessKey)

	// ONE_HOUR < AssumeRole
	// TWELVE_HOUR < GetSessionToken
	// ONE_HOUR < GetFederationToken
	expiration := time.Now().Add(time.Hour).Format("2006-01-02T15:04:05Z")

	data := []byte(accessKey + "0123456789")
	secretKey := base64.StdEncoding.EncodeToString(data)

	data = []byte(sessionTokenXML[:177])
	token := base64.StdEncoding.EncodeToString(data)

	respVar := GetFederationTokenVars{userStrng, accessKey, secretKey, token, accountID, expiration, requestID}
	tmpl, err := template.New("resp").Parse(getFederationTokenXML)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
