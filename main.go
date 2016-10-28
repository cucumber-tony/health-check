package main

import (
	"flag"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

var (
	debug    = flag.Bool("debug", false, "Enable debuggin")
	pprof    = flag.Bool("pprof", false, "Enable PPROF")
	HTTPPort = flag.String("http-port", "3000", "Set the port for HTTP")
	URL      = flag.String("url", "/_health", "Set the check URL")
	Method   = flag.String("method", "GET", "Set the check method")
	Token    = flag.String("token", "", "Set the check auth token")
	Process  = flag.String("process", "", "Set the process names to monitor")

	processes []string
)

func main() {
	flag.Parse()

	processes = strings.Split(*Process, ",")

	log.Print(processes)
	if len(processes) == 0 {
		log.Fatal("No processes to monitor!")
	}

	SetupRoutes()
}

// Check with match the token sent with the token arg to authorise the requests.
// Leave *Token blank to prevent a check
func Check(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if *Token != "" {
			token := r.URL.Query().Get("access_token")
			if token != *Token {
				http.Error(w, "Invalid token ", http.StatusUnauthorized)
				return
			}
		}
		fn(w, r)
		return
	}
}

// SetupRoutes creates the routes for the API server
func SetupRoutes() {
	log.Print("Setting up routes")
	r := mux.NewRouter()
	r.HandleFunc(*URL, Check(Health())).Methods(*Method)
	log.Fatal(http.ListenAndServe(":"+*HTTPPort, handlers.LoggingHandler(os.Stdout, r)))
}

// Health is used by a health check
func Health() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		for _, x := range processes {

			// Get the PIDS from the process names
			output, err := exec.Command("pgrep", x).Output()
			if err != nil {
				log.Print(string(output))
				w.WriteHeader(404)
				// a, _ := json.Marshal(response)
				// w.Write(a)
				return
			}

			// Reformat the output and take the first ID from the list
			ps := string(output)
			pids := strings.Split(ps, "\n")

			if len(pids) == 0 {
				log.Print("No PIDS to check")
				w.WriteHeader(404)
				return
			}

			// Convert to numeric IDS
			p, err := strconv.Atoi(pids[0])
			if err != nil {
				log.Print(err)
				w.WriteHeader(404)
				return
			}

			log.Printf("Checking processID: %d", p)

			// Find and check the process is running
			process, err := os.FindProcess(p)
			if err != nil {
				log.Printf("Failed to find process: %s\n", err)
				w.WriteHeader(404)
				return
			}

			// Check if the process is actually running or not...
			err = process.Signal(syscall.Signal(0))
			log.Printf("process.Signal on pid %d returned: %v\n", p, err)

			// If the error is nil, we should return 200
			if err != nil {
				log.Printf("Process with ID %d is NOT running\n", p)
				w.WriteHeader(404)
				return
			}
		}

		w.WriteHeader(200)
		return
	})
}
