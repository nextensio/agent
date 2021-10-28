package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	common "gitlab.com/nextensio/common/go"
)

var keepcount = 0
var publicIP = ""
var localIP = ""

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

type KeepaliveRequest struct {
	Device  string `json:"device"`
	Gateway uint32 `json:"gateway"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

type KeepaliveResponse struct {
	Result  string `json:"Result"`
	Version string `json:"version"`
}

func getPublicIP() {
	// we are using a pulic IP API, we're using ipify here, below are some others
	// https://www.ipify.org
	// http://myexternalip.com
	// http://api.ident.me
	// http://whatismyipaddress.com/api
	url := "https://api.ipify.org?format=text"
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	publicIP = fmt.Sprintf("%s", ip)
}

// Get preferred outbound ip of this machine
func getLocalIP() {
	var conn net.Conn
	var err error
	for {
		conn, err = net.Dial("udp", "8.8.8.8:80")
		if err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}

	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP = localAddr.IP.String()
}

func ControllerKeepalive(lg *log.Logger, controller string, sharedKey string, version string) bool {
	var ka KeepaliveResponse
	// TODO: Once we start using proper certs for our production clusters, make this
	// accept_invalid_certs true only for test environment. Even test environments ideally
	// should have verifiable certs via a test.nextensio.net domain or something
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// Well, I dont know if ipfy will block us if we keep pounding it, the public
	// IP for a connector usually doesnt change since its a server instance, so go slow
	if (keepcount % 100) == 0 {
		getPublicIP()
	}
	keepcount += 1
	kr := KeepaliveRequest{Device: deviceName, Gateway: gatewayIP, Version: version, Source: publicIP + ":" + localIP}
	body, err := json.Marshal(kr)
	if err != nil {
		lg.Println("Unable to make keepalive body")
		return false
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("POST", "https://"+controller+"/api/v1/global/add/keepaliverequest", bytes.NewBuffer(body))
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
