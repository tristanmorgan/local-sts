package iam

import (
	"encoding/base64"
	"log"
	"net/http"
	"text/template"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tristanmorgan/local-sts/metrics"
	"github.com/tristanmorgan/local-sts/sts"
)

const createAccessKeyTemplate = `<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <CreateAccessKeyResult>
    <AccessKey>
      <UserName>{{ .UserStrng }}</UserName>
      <AccessKeyId>{{ .AccessKey }}</AccessKeyId>
      <Status>Active</Status>
      <SecretAccessKey>{{ .SecretKey }}</SecretAccessKey>
    </AccessKey>
  </CreateAccessKeyResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
  </ResponseMetadata>
</CreateAccessKeyResponse>`

// CreateAccessKeyVars holds the template variables for IAM CreateAccessKey API responses.
type CreateAccessKeyVars struct {
	AccessKey string
	SecretKey string
	RequestID string
	UserStrng string
}

// CreateAccessKey handles API calls to CreateAccessKey
func CreateAccessKey(w http.ResponseWriter, req *http.Request, requestID string) {
	// Action=CreateAccessKey&Version=2011-06-15&UserName=Bob
	// Extract accessKey from Authorization header
	accessKey, err := sts.GetAuthorisation(req)
	if err != nil {
		metrics.ErrorCount.With(prometheus.Labels{"error": "Unauthorized"}).Inc()
		sts.UnauthorizedResponse(requestID, w)
		return
	}

	accessKey = sts.CreateNewKey(accessKey)
	data := []byte(accessKey + "0123456789")
	secretKey := base64.StdEncoding.EncodeToString(data)

	userStr := sts.GetFakeUser(accessKey)

	respVar := CreateAccessKeyVars{accessKey, secretKey, requestID, userStr}
	tmpl, err := template.New("resp").Parse(createAccessKeyTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
