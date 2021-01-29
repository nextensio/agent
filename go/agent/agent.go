package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	NXT_AGENT_PROXY  = 8080
	NXT_OKTA_RESULTS = 8081
	NXT_OKTA_LOGIN   = 8180
)

type registrationInfo struct {
	Host        string   `json:"gateway"`
	AccessToken string   `json:"accessToken"`
	ConnectID   string   `json:"connectid"`
	Domains     []string `json:"domains"`
	CACert      []rune   `json:"cacert"`
	Userid      string   `json:"userid"`
}

var controller string
var regInfo registrationInfo
var nxtOnboarded bool
var nxtOnboardPending bool
var services []string

func oktaLogin() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./public/login.html")
	})
	addr := fmt.Sprintf(":%d", NXT_OKTA_LOGIN)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func nxtOnboard() {
	for {
		resp, err := http.Get("http://" + controller + "/api/v1/onboard/" + regInfo.AccessToken)
		if err == nil {
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				err = json.Unmarshal(body, &regInfo)
				if err == nil {
					nxtOnboarded = true
					nxtOnboardPending = false
					services = append(services, regInfo.ConnectID)
					fmt.Println("New services", services)
					break
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func oktaResults() {
	mux := http.NewServeMux()
	mux.HandleFunc("/accessid/", func(w http.ResponseWriter, r *http.Request) {
		regInfo.AccessToken = r.URL.Query().Get("access")
		if !nxtOnboarded && !nxtOnboardPending {
			go nxtOnboard()
		}
		w.WriteHeader(http.StatusOK)
	})
	addr := fmt.Sprintf(":%d", NXT_OKTA_RESULTS)
	http.ListenAndServe(addr, mux)
}

func args() {
	c := flag.String("controller", "server.nextensio.net:8080", "controller host:port")
	s := flag.String("service", "", "services advertised by this agent")
	flag.Parse()
	controller = *c
	svcs := strings.TrimSpace(*s)
	services = strings.Fields(svcs)
	fmt.Println("controller", controller, "services", services)
}

func main() {
	args()
	go oktaLogin()
	oktaResults()
}
