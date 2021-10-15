package main

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	common "gitlab.com/nextensio/common/go"
)

const (
	UDP_AGER = 5 * time.Minute
	// Well, for tcp its more granular than this, half closed sessions
	// have a shorter timeout. Its a TODO to implement that. But then
	// at the transport layer, we dont have the concept of half closed
	TCP_AGER = 4 * time.Hour
)

type ConnStats struct {
	Conn common.Transport
	Rx   uint64
	Tx   uint64
}

type Domain struct {
	Name string `json:"name" bson:"name"`
}

type RegistrationInfo struct {
	Gateway     string   `json:"gateway"`
	AccessToken string   `json:"accessToken"`
	ConnectID   string   `json:"connectid"`
	Cluster     string   `json:"cluster"`
	Domains     []Domain `json:"domains"`
	CACert      []rune   `json:"cacert"`
	Userid      string   `json:"userid"`
	Tenant      string   `json:"tenant"`
	Services    []string `json:"services"`
	Version     string   `json:"version"`
	Keepalive   uint     `json:"keepalive"`
}

func ControllerOnboard(lg *log.Logger, controller string, sharedKey string) bool {
	// TODO: Once we start using proper certs for our production clusters, make this
	// accept_invalid_certs true only for test environment. Even test environments ideally
	// should have verifiable certs via a test.nextensio.net domain or something
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", "https://"+controller+"/api/v1/global/get/onboard", nil)
	if err == nil {
		req.Header.Add("Authorization", "Bearer "+sharedKey)
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				regInfoLock.Lock()
				err = json.Unmarshal(body, &regInfo)
				regInfoLock.Unlock()
				if err == nil {
					return true
				}
			}
		} else {
			lg.Println("Onboard request failed", err)
		}
	}
	lg.Println("Onboarding failed", err)
	return false
}

type KeepaliveResponse struct {
	Result  string `json:"Result"`
	Version string `json:"version"`
}

func ControllerKeepalive(lg *log.Logger, controller string, sharedKey string, version string, uuid string) bool {
	var ka KeepaliveResponse
	// TODO: Once we start using proper certs for our production clusters, make this
	// accept_invalid_certs true only for test environment. Even test environments ideally
	// should have verifiable certs via a test.nextensio.net domain or something
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", "https://"+controller+"/api/v1/global/get/keepalive/"+version+"/"+uuid, nil)
	if err == nil {
		req.Header.Add("Authorization", "Bearer "+sharedKey)
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				err = json.Unmarshal(body, &ka)
				if err == nil {
					if ka.Result == "ok" {
						if version != ka.Version {
							lg.Println("Keepalive mismatch", version, ka.Version)
							return true
						}
					}
				}
			}
		} else {
			lg.Println("Keepalive request failed", err)
		}
	}
	if ka.Result != "ok" {
		lg.Println("Keepalive failed", err, ka)
	}
	return false
}
