package iam

import (
	"log"
	"net/http"
	"text/template"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tristanmorgan/local-sts/metrics"
	"github.com/tristanmorgan/local-sts/sts"
)

const listUsersTemplate = `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
 <ListUsersResult>
    <Users>
       <member>
          <UserId>{{ .AccessKey }}</UserId>
          <Path>/</Path>
          <UserName>{{ .UserStrng }}</UserName>
          <Arn>arn:aws:iam::{{ .AccountID }}:user/{{ .UserStrng }}</Arn>
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

const listRolesTemplate = `<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
<ListRolesResult>
  <IsTruncated>false</IsTruncated>
  <Roles>
    <member>
      <Path>/</Path>
      <Arn>arn:aws:iam::{{ .AccountID }}:role/S3Access</Arn>
      <RoleName>S3Access</RoleName>
      <AssumeRolePolicyDocument>
        {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}
      </AssumeRolePolicyDocument>
      <CreateDate>2012-05-09T15:45:45Z</CreateDate>
      <RoleId>{{ .AccessKey }}</RoleId>
    </member>
  </Roles>
</ListRolesResult>
<ResponseMetadata>
  <RequestId>{{ .RequestID}}</RequestId>
</ResponseMetadata>
</ListRolesResponse>`

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

// ListRolesVars holds the template variables for IAM ListRoles API responses.
type ListRolesVars struct {
	AccountID string
	AccessKey string
	RequestID string
}

// ListUsers handles API calls to ListUsers
func ListUsers(w http.ResponseWriter, req *http.Request, requestID string) {
	// Action=ListUsers&Version=2011-06-15
	// Extract accessKey from Authorization header
	// Format: AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/iam/aws4_request,...
	accessKey, err := sts.GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		sts.UnauthorizedResponse(requestID, w)
		return
	}
	accountID := sts.DecodeAID(accessKey)
	userStr := sts.GetFakeUser(accessKey)
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
func ListAccessKeys(w http.ResponseWriter, req *http.Request, requestID string) {
	accessKey, err := sts.GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		sts.UnauthorizedResponse(requestID, w)
		return
	}
	if len(accessKey) > 4 {
		accessKey = "AKIA" + accessKey[4:]
	}
	userStr := sts.GetFakeUser(accessKey)

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

// ListRoles handles API calls to ListAccessKeys
func ListRoles(w http.ResponseWriter, req *http.Request, requestID string) {
	accessKey, err := sts.GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		sts.UnauthorizedResponse(requestID, w)
		return
	}
	accountID := sts.DecodeAID(accessKey)
	if len(accessKey) > 4 {
		accessKey = "AROA" + accessKey[4:]
	}

	respVar := ListRolesVars{accountID, accessKey, requestID}
	tmpl, err := template.New("resp").Parse(listRolesTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
