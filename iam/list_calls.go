package iam

import (
	"errors"
	"log"
	"net/http"
	"regexp"
	"text/template"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tristanmorgan/local-sts/metrics"
	"github.com/tristanmorgan/local-sts/sts"
)

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

const listRolesTemplate = `<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
<ListRolesResult>
  <IsTruncated>false</IsTruncated>
  <Roles>
    <member>
      <Path>/application_abc/component_xyz/</Path>
      <Arn>arn:aws:iam::{{ .AccountID }}:role/application_abc/component_xyz/S3Access</Arn>
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
func ListAccessKeys(w http.ResponseWriter, req *http.Request) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	accessKey, err := GetAuthorisation(req)
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
func ListRoles(w http.ResponseWriter, req *http.Request) {
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
