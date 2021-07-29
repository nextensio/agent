package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	websock "gitlab.com/nextensio/common/go/transport/websocket"
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
	Name    string `json:"name" bson:"name"`
	NeedDns bool   `json:"needdns" bson:"needdns"`
	DnsIP   string `json:"dnsip" bson:"dnsip"`
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
	Version     uint64   `json:"version"`
	Keepalive   uint     `json:"keepalive"`
}

func ControllerOnboard(lg *log.Logger, controller string, accessToken string) bool {
	// TODO: Once we start using proper certs for our production clusters, make this
	// accept_invalid_certs true only for test environment. Even test environments ideally
	// should have verifiable certs via a test.nextensio.net domain or something
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
	Version uint64 `json:"version"`
}

func ControllerKeepalive(lg *log.Logger, controller string, accessToken string, version uint64, uuid string) bool {
	var ka KeepaliveResponse
	// TODO: Once we start using proper certs for our production clusters, make this
	// accept_invalid_certs true only for test environment. Even test environments ideally
	// should have verifiable certs via a test.nextensio.net domain or something
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	vn := fmt.Sprintf("%d", version)
	req, err := http.NewRequest("GET", "https://"+controller+"/api/v1/global/get/keepalive/"+vn+"/"+uuid, nil)
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

// Create a websocket session to the gateway
func dialWebsocket(ctx context.Context, lg *log.Logger, regInfo *RegistrationInfo, c chan common.NxtStream) common.Transport {
	regInfoLock.RLock()
	req := http.Header{}
	req.Add("x-nextensio-connect", regInfo.ConnectID)
	// Ask for a keepalive to be sent once in two seconds
	wsock := websock.NewClient(ctx, lg, []byte(string(regInfo.CACert)), regInfo.Gateway, regInfo.Gateway, 443, req, 2*1000)
	regInfoLock.RUnlock()
	if err := wsock.Dial(c); err != nil {
		lg.Println("Cannot dial websocket", err, regInfo.ConnectID)
		return nil
	}

	return wsock
}

// Create a tunnel/session to the gateway with the given encap. We can expect
// more and more encap types to get added here over time (like rsocket for example)
func DialGateway(ctx context.Context, lg *log.Logger, encap string, regInfo *RegistrationInfo, c chan common.NxtStream) common.Transport {
	if encap == "websocket" {
		return dialWebsocket(ctx, lg, regInfo, c)
	} else {
		panic(encap)
	}
}

// Protobuf encode the device onboard information and send to the gateway
// Remember the transport need not be TCP, so the message delivery is not
// guaranteed, so we wait for a response for some time and if we dont get
// one, then we resend. Hence set the socket to blocking-with-timeout to
// read a response with a timeout. We try this a few times and give up if
// we still cant confirm that our onboard info was received by the gateway
func OnboardTunnel(lg *log.Logger, tunnel common.Transport, isAgent bool, regInfo *RegistrationInfo, uuid string) *common.NxtError {
	regInfoLock.RLock()
	p := &nxthdr.NxtOnboard{
		Agent: isAgent, Userid: regInfo.Userid, Uuid: uuid,
		AccessToken: regInfo.AccessToken, Services: regInfo.Services,
		Cluster:   regInfo.Cluster,
		ConnectId: regInfo.ConnectID,
	}
	regInfoLock.RUnlock()

	hdr := nxthdr.NxtHdr{Hdr: &nxthdr.NxtHdr_Onboard{p}}
	err := tunnel.Write(&hdr, net.Buffers{})
	if err != nil {
		return err
	}
	return nil
}
