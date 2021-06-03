package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

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

type AuthenticateOpts struct {
	MultiOptionalFactorEnroll bool `bson:"multiOptionalFactorEnroll" json:"multiOptionalFactorEnroll"`
	WarnBeforePasswordExpired bool `bson:"warnBeforePasswordExpired" json:"warnBeforePasswordExpired"`
}

type Authenticate struct {
	Username string           `bson:"username" json:"username"`
	Password string           `bson:"password" json:"password"`
	Options  AuthenticateOpts `bson:"options" json:"options"`
}

type sessionToken struct {
	Token string `bson:"sessionToken" json:"sessionToken"`
}

type accessIdTokens struct {
	AccessToken string `bson:"access_token" json:"access_token"`
	IdToken     string `bson:"id_token" json:"id_token"`
}

func authenticate(IDP string, clientid string, username string, password string) *accessIdTokens {

	auth := Authenticate{
		Username: username,
		Password: password,
		Options: AuthenticateOpts{
			MultiOptionalFactorEnroll: false,
			WarnBeforePasswordExpired: false,
		},
	}
	body, err := json.Marshal(auth)
	if err != nil {
		return nil
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("POST", IDP+"/api/v1/authn", bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("Authentication request failed", err)
		return nil
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Authentication failed: ", err, resp)
		return nil
	}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Authentication response body read failed", err)
		return nil
	}
	var stoken sessionToken
	err = json.Unmarshal(body, &stoken)
	if err != nil {
		fmt.Println("Authentication unmarshall failed", err)
		return nil
	}

	verifier, _ := verifier()
	challenge := verifier.CodeChallengeS256()

	queries := "client_id=" + clientid + "&redirect_uri=http://localhost:8180/&response_type=code&scope=openid&"
	queries = queries + "&state=test&prompt=none&response_mode=query&code_challenge_method=S256"
	queries = queries + "&code_challenge=" + challenge + "&sessionToken=" + stoken.Token
	req, err = http.NewRequest("GET", IDP+"/oauth2/default/v1/authorize?"+queries, nil)
	if err != nil {
		fmt.Println("Authorize token request failed", err)
		return nil
	}
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println("Authorization request failed: ", err, resp)
		return nil
	}
	reg, _ := regexp.Compile("http://localhost:8180/\\?code=(.*)&state=test")
	match := reg.FindStringSubmatch(resp.Header.Get("Location"))
	if len(match) != 2 {
		fmt.Println("Bad redirect uri")
		return nil
	}
	queries = "client_id=" + clientid + "&redirect_uri=http://localhost:8180/&response_type=code&scope=openid"
	queries = queries + fmt.Sprintf("&grant_type=authorization_code&code=%s&code_verifier=%s", match[1], verifier.Value)
	req, err = http.NewRequest("POST", IDP+"/oauth2/default/v1/token?"+queries, nil)
	if err != nil {
		fmt.Println("Session token request failed", err)
		return nil
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println("Session token failed: ", err, resp)
		return nil
	}
	body, err = ioutil.ReadAll(resp.Body)
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
