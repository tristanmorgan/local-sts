package iam

import (
	"log"
	"net/http"
	"text/template"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tristanmorgan/local-sts/metrics"
	"github.com/tristanmorgan/local-sts/sts"
)

const getUserTemplate = `<GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
 <GetUserResult>
    <User>
        <UserId>{{ .AccessKey }}</UserId>
        <Path>/division_abc/subdivision_xyz/engineering/</Path>
        <UserName>{{ .UserStrng }}</UserName>
        <Arn>arn:aws:iam::{{ .AccountID }}:user/division_abc/subdivision_xyz/engineering/{{ .UserStrng }}</Arn>
        <CreateDate>2012-09-05T19:38:48Z</CreateDate>
        <PasswordLastUsed>2014-09-08T21:47:36Z</PasswordLastUsed>
    </User>
    <IsTruncated>false</IsTruncated>
 </GetUserResult>
 <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
 </ResponseMetadata>
</GetUserResponse>`

const getRoleTemplate = `<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
<GetRoleResult>
  <Role>
    <Path>/application_abc/component_xyz/</Path>
    <Arn>arn:aws:iam::{{ .AccountID }}:role/application_abc/component_xyz/S3Access</Arn>
    <RoleName>S3Access</RoleName>
    <AssumeRolePolicyDocument>
      {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
      "Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}
    </AssumeRolePolicyDocument>
    <CreateDate>2012-05-08T23:34:01Z</CreateDate>
    <RoleId>{{ .AccessKey }}</RoleId>
    <RoleLastUsed>
      <LastUsedDate>2019-11-20T17:09:20Z</LastUsedDate>
      <Region>us-east-1</Region>
    </RoleLastUsed>
  </Role>
</GetRoleResult>
<ResponseMetadata>
  <RequestId>{{ .RequestID }}</RequestId>
</ResponseMetadata>
</GetRoleResponse>`

// GetUserVars holds the template variables for IAM GetUser API responses.
type GetUserVars struct {
	AccountID string
	AccessKey string
	RequestID string
	UserStrng string
}

// GetRoleVars holds the template variables for IAM GetRole API responses.
type GetRoleVars struct {
	AccountID string
	AccessKey string
	RequestID string
}

// GetUser handles API calls to GetUser
func GetUser(w http.ResponseWriter, req *http.Request) {
	// Action=GetUser&Version=2011-06-15
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	// Extract accessKey from Authorization header
	accessKey, err := GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		sts.UnauthorizedResponse(requestID, w)
		return
	}
	accountID := sts.DecodeAID(accessKey)
	userStr := sts.GetFakeUser(accessKey)
	if len(accessKey) > 4 {
		accessKey = "AIDA" + accessKey[4:]
	}

	respVar := GetUserVars{accountID, accessKey, requestID, userStr}
	tmpl, err := template.New("resp").Parse(getUserTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}

// GetRole handles API calls to GetRole
func GetRole(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	accessKey, err := GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		sts.UnauthorizedResponse(requestID, w)
		return
	}
	accountID := sts.DecodeAID(accessKey)
	if len(accessKey) > 4 {
		accessKey = "AROA" + accessKey[4:]
	}

	respVar := GetRoleVars{accountID, accessKey, requestID}
	tmpl, err := template.New("resp").Parse(getRoleTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
