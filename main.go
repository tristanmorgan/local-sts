package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
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

const keyInfoTemplate = `<GetAccessKeyInfoResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetAccessKeyInfoResult>
    <Account>{{ .AccountId }}</Account>    
  </GetAccessKeyInfoResult>
 <ResponseMetadata>
    <RequestId>{{ .RequestId }}</RequestId>
 </ResponseMetadata>
</GetAccessKeyInfoResponse>`

func decodeARN(access_key_id string) (decode_account_id string) {
	awsTable := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	// Extract characters 3-12 (10 characters)
	if len(access_key_id) < 13 {
		return "000000000000"
	}
	paddedNo := access_key_id[3:13]

	// Base32 decode
	var decimal uint64 = 0
	for _, char := range paddedNo {
		index := -1
		for i, c := range awsTable {
			if c == char {
				index = i
				break
			}
		}
		if index == -1 {
			return "000000000000"
		}
		decimal = (decimal << 5) + uint64(index)
	}

	// Shift right by 4 bits and mask with 40-bit mask
	mask := uint64((1 << 40) - 1)
	decimal = (decimal >> 4) & mask

	// Format as 12-digit string with leading zeros
	return fmt.Sprintf("%012d", decimal)
}

type ResponseVars struct {
	AccountId string
	AccessKey string
	RequestId string
}

func stsCall(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		stsCallerIdentityCall(w, req)
	} else if req.Method == http.MethodGet {
		stsKeyInfoCall(w, req)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func stsCallerIdentityCall(w http.ResponseWriter, req *http.Request) {
	// Action=GetCallerIdentity&Version=2011-06-15
	request_id := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", request_id)
	w.Header().Set("Content-Type", "text/xml")

	// Extract access_key from Authorization header
	// Format: AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/sts/aws4_request,...
	access_key := ""
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		// Use regex to extract access key from Credential=<ACCESS_KEY>/...
		re := regexp.MustCompile(`Credential=([A-Z0-9]+)/`)
		matches := re.FindStringSubmatch(authHeader)
		if len(matches) > 1 {
			access_key = matches[1]
		}
	}
	account_id := decodeARN(access_key)

	respVar := ResponseVars{account_id, access_key, request_id}
	tmpl, err := template.New("resp").Parse(UserIDTemplate)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(w, respVar)
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}
}

func stsKeyInfoCall(w http.ResponseWriter, req *http.Request) {
	request_id := uuid.New().String()
	w.Header().Set("x-amzn-RequestId", request_id)
	w.Header().Set("Content-Type", "text/xml")

	// Extract access_key from query parameter AccessKeyId
	access_key := req.URL.Query().Get("AccessKeyId")
	if access_key == "" {
		access_key = "AKIAI44QH8DHBEXAMPLE"
	}
	account_id := decodeARN(access_key)

	respVar := ResponseVars{account_id, access_key, request_id}
	tmpl, err := template.New("resp").Parse(keyInfoTemplate)
	if err != nil {
		panic(err)
	}
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
