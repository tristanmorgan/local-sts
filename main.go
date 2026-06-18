package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tristanmorgan/local-sts/sts"
)

// Version number constant.
const Version = "0.0.1"

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
			http.Error(w, "Form Validadtion Error", http.StatusBadRequest)
		}
		action := req.FormValue("Action")
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
			http.Error(w, "Action Not Allowed", http.StatusBadRequest)
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func health(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Server", "local-sts/"+Version+" (+"+Homepage+")")
	_, _ = io.WriteString(w, "Healthy.\n")
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
