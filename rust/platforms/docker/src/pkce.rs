use log::error;
use regex::Regex;
use serde::{Deserialize, Serialize};

const TEST_PROFILE: IdpProfile = IdpProfile {
    idp: "https://dev-635657.okta.com",
    client_id: "0oaz5lndczD0DSUeh4x6",
};
const PROD_PROFILE: IdpProfile = IdpProfile {
    idp: "https://login.nextensio.net/",
    client_id: "0oav0q3hn65I4Zkmr5d6",
};

struct IdpProfile<'a> {
    idp: &'a str,
    client_id: &'a str,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize)]
struct AuthenticateOpts {
    multiOptionalFactorEnroll: bool,
    warnBeforePasswordExpired: bool,
}
#[derive(Debug, Serialize)]
struct Authenticate {
    username: String,
    password: String,
    options: AuthenticateOpts,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct SessionToken {
    sessionToken: String,
}
#[derive(Debug, Deserialize)]
pub struct AccessIdTokens {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: String,
}

fn authn_username_pwd(
    client: &mut reqwest::Client,
    username: &str,
    password: &str,
) -> Option<SessionToken> {
    let idp;
    if std::env::var("NXT_TESTING").is_ok() {
        idp = TEST_PROFILE.idp;
    } else {
        idp = PROD_PROFILE.idp;
    }
    let auth = Authenticate {
        username: username.to_string(),
        password: password.to_string(),
        options: AuthenticateOpts {
            multiOptionalFactorEnroll: false,
            warnBeforePasswordExpired: false,
        },
    };
    let j = serde_json::to_string(&auth).unwrap();
    let url = format!("{}/api/v1/authn", idp);
    let resp = client
        .post(&url)
        .body(j)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .send();
    match resp {
        Ok(mut res) => {
            if res.status().is_success() {
                let stoken: std::result::Result<SessionToken, reqwest::Error> = res.json();
                match stoken {
                    Ok(t) => {
                        return Some(t);
                    }
                    Err(e) => {
                        error!("HTTP authn body failed {:?}", e);
                        println!(
                            "Authentication failed ({}), please check username/password",
                            res.status()
                        )
                    }
                }
            } else {
                error!("HTTP authn result {}, failed", res.status());
                println!(
                    "Authentication failed ({}), please check username/password",
                    res.status()
                )
            }
        }
        Err(e) => {
            error!("HTTP authn failed {:?}", e);
        }
    }

    None
}

fn authorize(client: &mut reqwest::Client, t: SessionToken) -> (String, oauth2::PkceCodeVerifier) {
    let idp;
    let client_id;
    if std::env::var("NXT_TESTING").is_ok() {
        idp = TEST_PROFILE.idp;
        client_id = TEST_PROFILE.client_id;
    } else {
        idp = PROD_PROFILE.idp;
        client_id = PROD_PROFILE.client_id;
    }
    let (code_challenge, code_verify) = oauth2::PkceCodeChallenge::new_random_sha256();
    let mut queries = format!("client_id={}&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access", client_id);
    queries = format!(
        "{}&state=test&prompt=none&response_mode=query&code_challenge_method=S256",
        queries
    );
    queries = format!(
        "{}&code_challenge={}&sessionToken={}",
        queries,
        code_challenge.as_str(),
        t.sessionToken
    );
    let authorize = format!("{}/oauth2/default/v1/authorize?{}", idp, queries);
    let resp = client.get(&authorize).send();
    match resp {
        Ok(res) => {
            if res.status().is_success() || res.status().as_u16() == 302 {
                let hdrs = res.headers();
                if hdrs.contains_key("Location") {
                    let re = Regex::new(r"http://localhost:8180/\?code=(.*)&state=test").unwrap();
                    match re.captures(hdrs.get("Location").unwrap().to_str().unwrap()) {
                        Some(r) => {
                            let code = r.get(1).map_or("", |m| m.as_str());
                            return (code.to_string(), code_verify);
                        }
                        None => {
                            error!("Bad redirect uri");
                        }
                    }
                } else {
                    error!("Bad redirect uri");
                }
            } else {
                error!("HTTP authorize result {}, failed", res.status());
            }
        }
        Err(e) => {
            error!("HTTP authorize body failed {:?}", e);
        }
    }
    ("".to_string(), code_verify)
}

pub fn get_tokens(
    client: &mut reqwest::Client,
    code: String,
    code_verify: oauth2::PkceCodeVerifier,
) -> Option<AccessIdTokens> {
    let idp;
    let client_id;
    if std::env::var("NXT_TESTING").is_ok() {
        idp = TEST_PROFILE.idp;
        client_id = TEST_PROFILE.client_id;
    } else {
        idp = PROD_PROFILE.idp;
        client_id = PROD_PROFILE.client_id;
    }
    let mut queries = format!("client_id={}&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access", client_id);
    queries = format!(
        "{}&grant_type=authorization_code&code={}&code_verifier={}",
        queries,
        code,
        code_verify.secret()
    );
    let url = format!("{}/oauth2/default/v1/token?{}", idp, queries);
    let resp = client
        .post(&url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("cache-control", "no-cache")
        .send();
    match resp {
        Ok(mut res) => {
            if res.status().is_success() {
                let token: std::result::Result<AccessIdTokens, reqwest::Error> = res.json();
                match token {
                    Ok(t) => return Some(t),
                    Err(e) => error!("Access token fail {}", e),
                }
            } else {
                error!("Access token response fail {}", res.status());
            }
        }
        Err(e) => {
            error!("Access token response error {}", e)
        }
    }
    None
}

pub fn authenticate(username: &str, password: &str) -> Option<AccessIdTokens> {
    let mut client = reqwest::Client::builder()
        .redirect(reqwest::RedirectPolicy::none())
        .build()
        .unwrap();
    if let Some(t) = authn_username_pwd(&mut client, username, password) {
        let (code, code_verifier) = authorize(&mut client, t);
        if code.is_empty() {
            return None;
        }
        return get_tokens(&mut client, code, code_verifier);
    }
    None
}

pub fn refresh(refresh: &str) -> Option<AccessIdTokens> {
    let idp;
    let client_id;
    if std::env::var("NXT_TESTING").is_ok() {
        idp = TEST_PROFILE.idp;
        client_id = TEST_PROFILE.client_id;
    } else {
        idp = PROD_PROFILE.idp;
        client_id = PROD_PROFILE.client_id;
    }

    let client = reqwest::Client::builder()
        .redirect(reqwest::RedirectPolicy::none())
        .build()
        .unwrap();

    let mut queries = format!("client_id={}&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access", client_id);
    queries = format!(
        "{}&grant_type=refresh_token&refresh_token={}",
        queries, refresh
    );
    let url = format!("{}/oauth2/default/v1/token?{}", idp, queries);
    let resp = client
        .post(&url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("cache-control", "no-cache")
        .send();
    match resp {
        Ok(mut res) => {
            if res.status().is_success() {
                let token: std::result::Result<AccessIdTokens, reqwest::Error> = res.json();
                match token {
                    Ok(t) => return Some(t),
                    Err(e) => error!("Refresh token fail {}", e),
                }
            } else {
                error!("Refresh token response fail {}", res.status());
            }
        }
        Err(e) => {
            error!("Refresh token response error {}", e)
        }
    }

    None
}
