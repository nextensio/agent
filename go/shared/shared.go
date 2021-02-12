package shared

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

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
	websock "gitlab.com/nextensio/common/transport/websocket"
)

const (
	NXT_OKTA_RESULTS = 8081
	NXT_OKTA_LOGIN   = 8180
)

const (
	UDP_AGER = 5 * time.Minute
	// Well, for tcp its more granular than this, half closed sessions
	// have a shorter timeout. Its a TODO to implement that. But then
	// at the transport layer, we dont have the concept of half closed
	TCP_AGER = 4 * time.Hour
)

type ConnStats struct {
	Conn net.Conn
	Rx   uint64
	Tx   uint64
}

type RegistrationInfo struct {
	Host        string   `json:"gateway"`
	AccessToken string   `json:"accessToken"`
	ConnectID   string   `json:"connectid"`
	Domains     []string `json:"domains"`
	CACert      []rune   `json:"cacert"`
	Userid      string   `json:"userid"`
	Services    []string `json:"services"`
}

var nxtOnboardPending bool
var nxtOnboarded bool

func oktaLogin(lg *log.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !nxtOnboarded {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Write([]byte(loginHtml))
		} else {
			w.WriteHeader(http.StatusCreated)
		}
	})
	addr := fmt.Sprintf(":%d", NXT_OKTA_LOGIN)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func nxtOnboard(lg *log.Logger, regInfo *RegistrationInfo, controller string, callback func(*log.Logger)) {
	for {
		// TODO: This is purely for the time being where we dont have proper certificates,
		// we work with self signed certs. And its difficult to get that into the android/ios
		// agents, so we just turn it off altogether, at any rate there is no production
		// image without proper certs, so this needs to be removed at that time
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("GET", "https://"+controller+"/api/v1/onboard/"+regInfo.AccessToken, nil)
		if err == nil {
			req.Header.Add("Authorization", "Bearer "+regInfo.AccessToken)
			resp, err := client.Do(req)
			if err == nil {
				body, err := ioutil.ReadAll(resp.Body)
				if err == nil {
					err = json.Unmarshal(body, regInfo)
					if err == nil {
						nxtOnboardPending = false
						nxtOnboarded = true
						regInfo.Services = append(regInfo.Services, regInfo.ConnectID)
						callback(lg)
						break
					}
				}
			} else {
				lg.Println("Onboard request failed", err)
			}
		}
		lg.Println("Onboarding failed, will retry again", err)
		time.Sleep(5 * time.Second)
	}
}

func oktaResults(lg *log.Logger, regInfo *RegistrationInfo, controller string, callback func(*log.Logger)) {
	mux := http.NewServeMux()
	mux.HandleFunc("/accessid/", func(w http.ResponseWriter, r *http.Request) {
		regInfo.AccessToken = r.URL.Query().Get("access")
		if !nxtOnboardPending {
			nxtOnboardPending = true
			go nxtOnboard(lg, regInfo, controller, callback)
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	})
	addr := fmt.Sprintf(":%d", NXT_OKTA_RESULTS)
	http.ListenAndServe(addr, mux)
}

func OktaInit(lg *log.Logger, regInfo *RegistrationInfo, controller string, callback func(*log.Logger)) {
	go oktaLogin(lg)
	go oktaResults(lg, regInfo, controller, callback)
}

// Create a websocket session to the gateway
func dialWebsocket(ctx context.Context, lg *log.Logger, regInfo *RegistrationInfo, c chan common.NxtStream) common.Transport {
	req := http.Header{}
	req.Add("x-nextensio-connect", regInfo.ConnectID)
	wsock := websock.NewClient(ctx, lg, []byte(string(regInfo.CACert)), regInfo.Host, regInfo.Host, 443, req)
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
	p := &nxthdr.NxtOnboard{
		Agent: isAgent, Userid: regInfo.Userid, Uuid: uuid,
		AccessToken: regInfo.AccessToken, Services: regInfo.Services,
	}
	hdr := nxthdr.NxtHdr{Hdr: &nxthdr.NxtHdr_Onboard{p}}
	retry := 0
	for {
		err := tunnel.Write(&hdr, net.Buffers{})
		if err != nil {
			return err
		}
		// Hope there are no links with RTT latency worse than 200 msecs!
		// Set the socket back to blocking read from wherever we return from here
		tunnel.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		hdr, _, err := tunnel.Read()
		if err != nil {
			switch e := err.Err.(type) {
			case net.Error:
				if e.Timeout() {
					retry++
					lg.Println("Onboard timed out, retry", retry)
					if retry >= 10 {
						lg.Println("Unable to read onboard response from gateway tunnel")
						tunnel.SetReadDeadline(time.Time{})
						return err
					}
				} else {
					tunnel.SetReadDeadline(time.Time{})
					return err
				}
			default:
				tunnel.SetReadDeadline(time.Time{})
				return err
			}
		} else {
			switch hdr.Hdr.(type) {
			case *nxthdr.NxtHdr_Onboard:
				lg.Println("Handshaked with gateway")
				tunnel.SetReadDeadline(time.Time{})
				return nil
			}
		}
	}
}
