package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"text/template"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version number constant.
const Version = "0.0.1"

// Homepage url.
const Homepage = "https://github.com/tristanmorgan/local-sts"

var (
	httpAddr = flag.String("listen", ":80", "Listen address")
	versDisp = flag.Bool("version", false, "Display version")
)

const UserIDTemplate = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
  <Arn>arn:aws:iam::{{ .AccountId }}:user/Alice</Arn>
  <UserId>{{ .AccessKey }}</UserId>
  <Account>{{ .AccountId }}</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>{{ .RequestId }}</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>`

func decodeARN(access_key_id string) (decode_account_id string) {
	//	awsTable := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	// implementation goes in here
	return "012345678901"
}

type ResponseVars struct {
	AccountId string
	AccessKey string
	RequestId string
}

func stsCall(w http.ResponseWriter, req *http.Request) {
	request_id := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", request_id)
	w.Header().Set("Content-Type", "text/xml")

	// access_key comes from Authorization header
	access_key := "AKIAI44QH8DHBEXAMPLE"
	account_id := decodeARN(access_key)
	// POST / HTTP/1.1
	// Accept-Encoding: identity
	// Content-Type: application/x-www-form-urlencoded
	// Authorization: AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/sts/aws4_request,
	//         SignedHeaders=host;user-agent;x-amz-date,
	//         Signature=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
	//
	// Action=GetCallerIdentity&Version=2011-06-15

	respVar := ResponseVars{account_id, access_key, request_id}
	tmpl, err := template.New("resp").Parse(UserIDTemplate)
	if err != nil {
		panic(err)
	}
	io.WriteString(w, UserIDTemplate)
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}

func health(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Server", "local-sts/"+Version+" (+"+Homepage+")")
	io.WriteString(w, "Healthy.\n")
}

func main() {
	flag.Parse()

	prometheus.MustRegister(version.NewCollector("local-sts"))
	if *versDisp {
		fmt.Printf("Version: v%s %s\n", Version, runtime.Version())
		fmt.Printf("Home Page: %s\n", Homepage)
		os.Exit(0)
	}

	log.Printf("Listening for incoming requests on TCP port '%s'...", *httpAddr)
	http.HandleFunc("/", stsCall)
	http.HandleFunc("/health", health)
	http.Handle("/metrics", promhttp.Handler())

	err := http.ListenAndServe(*httpAddr, nil)
	if err != nil {
		log.Fatal(err)
	}
}
