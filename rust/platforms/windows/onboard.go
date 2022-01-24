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
)

var keepcount = 0
var publicIP = ""

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
	SplitTunnel bool     `json:"splittunnel"`
}

func ControllerOnboard(lg *log.Logger, controller string, accessToken string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", "https://"+controller+"/api/v1/global/get/onboard", nil)
	if err == nil {
		req.Header.Add("Authorization", "Bearer "+accessToken)
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				regInfoLock.Lock()
				err = json.Unmarshal(body, &regInfo)
				agentOnboard()
				regInfoLock.Unlock()
				if err == nil {
					lg.Println("Agent succesfully onboarded")
					return true
				} else {
					lg.Println("Json unmarshall failed", err)
				}
			} else {
				lg.Println("Onboarding json failed", err)
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
	src := net.IP([]byte{
		uint8((defaultIP >> 24) & 0xFF),
		uint8((defaultIP >> 16) & 0xFF),
		uint8((defaultIP >> 8) & 0xFF),
		uint8(defaultIP & 0xFF),
	},
	)
	// If we dont do this bind, then this request might go via
	// nextensio gateway (if default internet service is configured)
	// and get us the IP of the connector !
	localTCPAddr := net.TCPAddr{
		IP: src,
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: &localTCPAddr,
				Timeout:   5 * time.Second,
			}).DialContext,
		},
	}
	// we are using a pulic IP API, we're using ipify here, below are some others
	// https://www.ipify.org
	// http://myexternalip.com
	// http://api.ident.me
	// http://whatismyipaddress.com/api
	url := "https://api.ipify.org?format=text"
	resp, err := client.Get(url)
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

func ControllerKeepalive(lg *log.Logger, controller string, accessToken string, version string, uuid string) bool {
	var ka KeepaliveResponse
	// TODO: Once we start using proper certs for our production clusters, make this
	// accept_invalid_certs true only for test environment. Even test environments ideally
	// should have verifiable certs via a test.nextensio.net domain or something
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// Well, I dont know if ipfy will block us if we keep pounding it
	if (keepcount % 4) == 0 {
		getPublicIP()
	}
	keepcount += 1
	kr := KeepaliveRequest{Device: sinfo.Hostname + ":" + sinfo.Platform, Gateway: getGatewayIP(), Version: version, Source: publicIP}
	body, err := json.Marshal(kr)
	if err != nil {
		lg.Println("Unable to make keepalive body")
		return false
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("POST", "https://"+controller+"/api/v1/global/add/keepaliverequest", bytes.NewBuffer(body))
	if err == nil {
		req.Header.Add("Authorization", "Bearer "+accessToken)
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
