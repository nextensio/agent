package main

import (
	"fmt"
	"log"
	"net/http"
)

const (
	NXT_AGENT_PROXY  = 8080
	NXT_OKTA_RESULTS = 8081
	NXT_OKTA_LOGIN   = 8180
)

func oktaLogin() {
	fs := http.FileServer(http.Dir("./public/"))
	http.Handle("/", fs)

	addr := fmt.Sprintf(":%d", NXT_OKTA_LOGIN)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	oktaLogin()
}
