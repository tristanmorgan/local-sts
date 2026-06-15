package main

import (
	"bytes"
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
)

// Version number constant.
const Version = "0.0.1"

// Homepage url.
const Homepage = "https://github.com/tristanmorgan/local-sts"

var (
	httpAddr = flag.String("listen", ":80", "Listen address")
	versDisp = flag.Bool("version", false, "Display version")
)

func decodeARN(accessKeyID string) (decodeAccountID string) {
	awsTable := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	// Extract characters 3-12 (10 characters)
	if len(accessKeyID) != 20 {
		return "000000000000"
	}
	paddedNo := accessKeyID[3:13]

	// Base32 decode
	var decimal uint64 = 0
	for _, char := range paddedNo {
		index := bytes.IndexByte([]byte(awsTable), byte(char))
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
