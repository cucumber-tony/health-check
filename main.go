package main

import (
	"bytes"
	"flag"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"crypto/tls"
	"time"
)

var (
	debug   = flag.Bool("debug", false, "Enable debuggin")
	pprof   = flag.Bool("pprof", false, "Enable PPROF")
	Host    = flag.String("host", "127.0.0.1", "Set the host for the check")
	Port    = flag.String("port", "3000", "Set the port for HTTP")
	URL     = flag.String("url", "/_health", "Set the check URL")
	Method  = flag.String("method", "GET", "Set the check method")
	Token   = flag.String("token", "", "Set the check auth token")
	Process = flag.String("process", "", "Set the process names to monitor")
	Webhook = flag.String("webhook", "", "Set a webhook URL")
	Type    = flag.String("type", "http", "Set the health check type")

	hostname string
	alert    bool
)

func main() {
	flag.Parse()
	alert = false
	hostname, _ = os.Hostname()

	if *Type == "http" {
		SetupRoutes()
	} else if *Type == "tcp" {
		tcp()
	}
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
	log.Fatal(http.ListenAndServe(":"+*Port, handlers.LoggingHandler(os.Stdout, r)))
}

// Health is used by a health check
func Health() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Get the PIDS from the process names
		output, err := exec.Command("pgrep", *Process).Output()
		if err != nil {
			log.Print(string(output))
			w.WriteHeader(404)
			go Message(*Process, true)
			return
		}

		// Reformat the output and take the first ID from the list
		ps := string(output)
		pids := strings.Split(ps, "\n")

		if len(pids) == 0 {
			log.Print("No PIDS to check")
			w.WriteHeader(404)
			go Message(*Process, true)
			return
		}

		// Convert to numeric IDS
		p, err := strconv.Atoi(pids[0])
		if err != nil {
			log.Print(err)
			w.WriteHeader(404)
			go Message(*Process, true)
			return
		}

		log.Printf("Checking processID: %d", p)

		// Find and check the process is running
		process, err := os.FindProcess(p)
		if err != nil {
			log.Printf("Failed to find process: %s\n", err)
			w.WriteHeader(404)
			go Message(*Process, true)
			return
		}

		// Check if the process is actually running or not...
		err = process.Signal(syscall.Signal(0))
		log.Printf("Signal on pid %d returned: %v\n", p, err)

		// If the error is nil, we should return 200
		if err != nil {
			log.Printf("Process with ID %d is NOT running\n", p)
			w.WriteHeader(404)
			go Message(*Process, true)
			return
		}

		w.WriteHeader(200)

		if alert == true {
			go Message(*Process, false)
		}
		return
	})
}

// Message sends a webhook to Slack of all things.
func Message(process string, alarm bool) bool {

	var jsonStr string

	if *Webhook != "" && Should(alarm) {
		if alarm {
			jsonStr = `{"username":"` + hostname + `", "text":"Houston we have a problem, the ` + process + ` process is no longer running or active."}`
		} else {
			jsonStr = `{"username":"` + hostname + `", "text":"Woop, the ` + process + ` process recovered!"}`
		}
		client := HttpClient()
		uri := *Webhook
		data := url.Values{}
		data.Set("payload", jsonStr)
		req, _ := http.NewRequest("POST", uri, bytes.NewBufferString(data.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("User-Agent", "Cucumber Bot")

		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
		}
	}

	return true
}

func Should(alarm bool) bool {

	if alarm == true && alert == false {
		// New alert
		alert = true
		return true

	} else if alarm == false && alert == true {
		// Close alert
		alert = false
		return true
	}
	return false
}

func HttpClient() *http.Client {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   3 * time.Second,
	}

	return client
}

func tcp() {
	// Listen for incoming connections.
	l, err := net.Listen("tcp", *Host+":"+*Port)
	if err != nil {
		log.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	log.Println("Listening on " + *Host + ":" + *Port)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			log.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(conn)
	}
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	_, err := conn.Read(buf)
	if err != nil {
		log.Println("Error reading:", err.Error())
	}
	// Send a response back to person contacting us.
	conn.Write([]byte("Message received."))
	// Close the connection when you're done with it.
	conn.Close()
}
