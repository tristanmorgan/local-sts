package main

import (
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promVersion "github.com/prometheus/common/version"
	"github.com/tristanmorgan/local-sts/iam"
	"github.com/tristanmorgan/local-sts/metrics"
	"github.com/tristanmorgan/local-sts/sts"
)

// Version number constant.
//
//go:embed .version
var Version string

// Homepage url.
const Homepage = "https://github.com/tristanmorgan/local-sts"

var (
	httpAddr   = flag.String("listen", ":8080", "Listen address")
	versDisp   = flag.Bool("version", false, "Display version")
	iamOnly    = flag.Bool("iam-only", false, "Serve only IAM actions")
	stsOnly    = flag.Bool("sts-only", false, "Serve only STS actions")
	iamActions = []string{"GetUser", "GetRole", "ListUsers", "ListAccessKeys", "ListRoles", "CreateAccessKey", "DeleteAccessKey", "DeleteUser", "DeleteRole"}
	stsActions = []string{"GetCallerIdentity", "GetAccessKeyInfo", "GetSessionToken", "GetFederationToken", "AssumeRole"}
)

func stsCall(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		requestID := uuid.New().String()
		w.Header().Set("x-amzn-RequestId", requestID)
		w.Header().Set("Content-Type", "text/xml")
		err := req.ParseForm()
		if err != nil {
			metrics.ErrorCount.With(prometheus.Labels{"error": "BadRequest"}).Inc()
			http.Error(w, "Form Validadtion Error", http.StatusBadRequest)
			return
		}
		action := req.FormValue("Action")
		metrics.ActionCount.With(prometheus.Labels{"action": action}).Inc()
		if *stsOnly && slices.Contains(iamActions, action) {
			metrics.ErrorCount.With(prometheus.Labels{"error": "BadRequest"}).Inc()
			http.Error(w, "Action Not Allowed", http.StatusBadRequest)
			return
		}
		if *iamOnly && slices.Contains(stsActions, action) {
			metrics.ErrorCount.With(prometheus.Labels{"error": "BadRequest"}).Inc()
			http.Error(w, "Action Not Allowed", http.StatusBadRequest)
			return
		}
		switch action {
		case "GetCallerIdentity":
			sts.GetCallerIdentity(w, req, requestID)
		case "GetAccessKeyInfo":
			sts.GetAccessKeyInfo(w, req, requestID)
		case "GetSessionToken":
			sts.GetSessionToken(w, req, requestID)
		case "GetFederationToken":
			sts.GetFederationToken(w, req, requestID)
		case "AssumeRole":
			sts.AssumeRole(w, req, requestID)
		case "GetUser":
			iam.GetUser(w, req, requestID)
		case "GetRole":
			iam.GetRole(w, req, requestID)
		case "ListUsers":
			iam.ListUsers(w, req, requestID)
		case "ListAccessKeys":
			iam.ListAccessKeys(w, req, requestID)
		case "ListRoles":
			iam.ListRoles(w, req, requestID)
		case "CreateAccessKey":
			iam.CreateAccessKey(w, req, requestID)
		case "DeleteAccessKey", "DeleteUser", "DeleteRole":
			iam.DeleteAction(w, req, action, requestID)
		default:
			metrics.ErrorCount.With(prometheus.Labels{"error": "BadRequest"}).Inc()
			http.Error(w, "Action Not Allowed", http.StatusBadRequest)
		}
	default:
		metrics.ErrorCount.With(prometheus.Labels{"error": "MethodNotAllowed"}).Inc()
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func health(w http.ResponseWriter, req *http.Request) {
	metrics.ActionCount.With(prometheus.Labels{"action": "health"}).Inc()
	w.Header().Set("Server", "local-sts/"+Version+" (+"+Homepage+")")
	_, _ = io.WriteString(w, "Healthy.\n")
}

func main() {
	flag.Parse()

	promVersion.Version = Version
	prometheus.MustRegister(version.NewCollector(metrics.PromNamespace))
	if *versDisp {
		fmt.Printf("%s\n", promVersion.Print(metrics.PromNamespace))
		fmt.Printf("Home Page: %s\n", Homepage)
		os.Exit(0)
	}
	if *iamOnly && *stsOnly {
		fmt.Println("-iam-only and -sts-only are mutually exclusive.")
		os.Exit(1)
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
