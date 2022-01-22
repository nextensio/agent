package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	oktajv "github.com/okta/okta-jwt-verifier-golang"
)

var tpl *template.Template
var state = "ApplicationState"
var code_verifier = ""

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

type CodeVerifier struct {
	Value string
}

func base64URLEncode(str []byte) string {
	encoded := base64.StdEncoding.EncodeToString(str)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)
	return encoded
}

func verifier() (*CodeVerifier, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 32, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(r.Intn(255))
	}
	return CreateCodeVerifierFromBytes(b)
}

func CreateCodeVerifierFromBytes(b []byte) (*CodeVerifier, error) {
	return &CodeVerifier{
		Value: base64URLEncode(b),
	}, nil
}

func (v *CodeVerifier) CodeChallengeS256() string {
	h := sha256.New()
	h.Write([]byte(v.Value))
	return base64URLEncode(h.Sum(nil))
}

type sessionToken struct {
	Token string `bson:"sessionToken" json:"sessionToken"`
}

type accessIdTokens struct {
	AccessToken string `bson:"access_token" json:"access_token"`
	IdToken     string `bson:"id_token" json:"id_token"`
	Refresh     string `bson:"refresh_token" json:"refresh_token"`
}

func refreshTokens(ISSUER string, CLIENT_ID string, refresh string) *accessIdTokens {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	queries := "client_id=" + CLIENT_ID + "&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access"
	queries = queries + fmt.Sprintf("&grant_type=refresh_token&refresh_token=%s", refresh)
	req, err := http.NewRequest("POST", ISSUER+"/v1/token?"+queries, nil)
	if err != nil {
		fmt.Println("Session token request failed", err)
		return nil
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Session token failed: ", err, resp)
		return nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Session token response body read failed", err)
		return nil
	}
	var aidTokens accessIdTokens
	err = json.Unmarshal(body, &aidTokens)
	if err != nil {
		fmt.Println("Access/Id unmarshall failed", err)
		return nil
	}
	return &aidTokens
}

func handleLogin() {

	http.HandleFunc("/", AuthCodeCallbackHandler)
	http.HandleFunc("/success", HomeHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)

	err := http.ListenAndServe("localhost:8180", nil)
	if err != nil {
		log.Printf("the HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "home.gohtml", nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	var redirectPath string

	cVerifier, _ := verifier()
	challenge := cVerifier.CodeChallengeS256()
	code_verifier = cVerifier.Value

	q := r.URL.Query()
	q.Add("client_id", CLIENT_ID)
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email offline_access")
	q.Add("redirect_uri", "http://localhost:8180/")
	q.Add("state", state)
	q.Add("code_challenge_method", "S256")
	q.Add("code_challenge", challenge)

	redirectPath = ISSUER + "/v1/authorize?" + q.Encode()
	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check the state that was returned in the query string is the same as the above state
	s := r.URL.Query().Get("state")
	if s != state {
		fmt.Fprintln(w, "The state was not as expected: ", s, state)
		return
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		fmt.Fprintln(w, "The code was not returned or is not accessible")
		return
	}

	exchange := exchangeCode(r.URL.Query().Get("code"), r)
	verificationError := verifyToken(&exchange)
	if verificationError != nil {
		fmt.Fprintln(w, verificationError)
		return
	}

	loggedIn = true
	TOKENS = &accessIdTokens{AccessToken: exchange.AccessToken, IdToken: exchange.IdToken}

	http.Redirect(w, r, "/success", http.StatusFound)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	loggedIn = false
	http.Redirect(w, r, "/success", http.StatusFound)
}

func exchangeCode(code string, r *http.Request) Exchange {
	url := ISSUER + "/v1/token"
	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	q := req.URL.Query()
	q.Add("client_id", CLIENT_ID)
	q.Add("redirect_uri", "http://localhost:8180/")
	q.Add("response_type", "code")
	q.Add("scope", "openid profile email offline_access")
	q.Add("grant_type", "authorization_code")
	q.Add("code", code)
	q.Add("code_verifier", code_verifier)
	req.URL.RawQuery = q.Encode()

	h := req.Header
	h.Add("Accept", "application/json")
	h.Add("cache-control", "no-cache")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	var exchange Exchange
	json.Unmarshal(body, &exchange)

	return exchange
}

func verifyToken(exchange *Exchange) error {
	tv := map[string]string{}
	tv["aud"] = "api://default"
	tv["cid"] = CLIENT_ID
	jv := oktajv.JwtVerifier{
		Issuer:           ISSUER,
		ClaimsToValidate: tv,
	}

	token, err := jv.New().VerifyAccessToken(exchange.AccessToken)
	if err != nil {
		return err
	}

	fmt.Println("Tenant: ", token.Claims["tenant"].(string),
		"userid: ", token.Claims["sub"].(string),
		"usertype: ", token.Claims["usertype"].(string))

	return nil
}
