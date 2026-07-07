package main

import (
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promVersion "github.com/prometheus/common/version"
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
	httpAddr = flag.String("listen", ":80", "Listen address")
	versDisp = flag.Bool("version", false, "Display version")
)

func stsCall(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		err := req.ParseForm()
		if err != nil {
			metrics.ErrorCount.With(prometheus.Labels{"error": "BadRequest"}).Inc()
			http.Error(w, "Form Validadtion Error", http.StatusBadRequest)
			return
		}
		action := req.FormValue("Action")
		metrics.ActionCount.With(prometheus.Labels{"action": action}).Inc()
		switch action {
		case "GetCallerIdentity":
			sts.GetCallerIdentity(w, req)
		case "GetAccessKeyInfo":
			sts.GetAccessKeyInfo(w, req)
		case "GetSessionToken":
			sts.GetSessionToken(w, req)
		case "GetFederationToken":
			sts.GetFederationToken(w, req)
		case "AssumeRole":
			sts.AssumeRole(w, req)
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

	log.Printf("Listening for incoming requests on TCP port '%s'...", *httpAddr)
	http.HandleFunc("/", stsCall)
	http.HandleFunc("/health", health)
	http.Handle("/metrics", promhttp.Handler())

	err := http.ListenAndServe(*httpAddr, nil)
	if err != nil {
		log.Fatal(err)
	}
}
