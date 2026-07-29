package iam

import (
	"log"
	"net/http"
	"text/template"

	"github.com/google/uuid"
)

const deleteTemplate = `<{{ .DelAction }}Response xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ResponseMetadata>
    <RequestId>{{ .RequestID }}</RequestId>
  </ResponseMetadata>
</{{ .DelAction }}Response>`

// DelActionVars holds the template variables for IAM delete API responses.
type DeleteVars struct {
	DelAction string
	RequestID string
}

// DeleteAction handles API calls many DeleteActions.
func DeleteAction(w http.ResponseWriter, req *http.Request, delAction string) {
	requestID := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", requestID)
	w.Header().Set("Content-Type", "text/xml")

	respVar := DeleteVars{delAction, requestID}
	tmpl, err := template.New("resp").Parse(deleteTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}
