use log::error;
use regex::Regex;
use rouille::router;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::Mutex;

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
    let (idp, _) = super::idp_client();

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

fn authorize_url(code_challenge: oauth2::PkceCodeChallenge, prompt: bool) -> String {
    let (idp, client_id) = super::idp_client();
    let mut queries = format!("client_id={}&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access", client_id);
    queries = format!(
        "{}&state=test&response_mode=query&code_challenge_method=S256",
        queries
    );
    if !prompt {
        queries = format!("{}&prompt=none", queries);
    }
    queries = format!("{}&code_challenge={}", queries, code_challenge.as_str(),);
    format!("{}/oauth2/default/v1/authorize?{}", idp, queries)
}

fn authorize(client: &mut reqwest::Client, t: SessionToken) -> (String, oauth2::PkceCodeVerifier) {
    let (code_challenge, code_verify) = oauth2::PkceCodeChallenge::new_random_sha256();
    let auth_url = format!(
        "{}&sessionToken={}",
        authorize_url(code_challenge, false),
        t.sessionToken
    );
    let resp = client.get(&auth_url).send();
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
    code_verify: Arc<Mutex<oauth2::PkceCodeVerifier>>,
) -> Option<AccessIdTokens> {
    let (idp, client_id) = super::idp_client();
    let mut queries = format!("client_id={}&redirect_uri=http://localhost:8180/&response_type=code&scope=openid%20offline_access", client_id);
    queries = format!(
        "{}&grant_type=authorization_code&code={}&code_verifier={}",
        queries,
        code,
        code_verify.lock().unwrap().secret()
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
        return get_tokens(&mut client, code, Arc::new(Mutex::new(code_verifier)));
    }
    None
}

pub fn refresh(refresh: &str) -> Option<AccessIdTokens> {
    let (idp, client_id) = super::idp_client();

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

pub fn web_server(schan: fltk::app::Sender<super::gui::Message>) {
    let onboarded = std::sync::atomic::AtomicBool::new(false);
    let (_, cv) = oauth2::PkceCodeChallenge::new_random_sha256();
    let code_verify = Arc::new(Mutex::new(cv));

    rouille::start_server("localhost:8180", move |request| {
        router!(request,
            (GET) (/success) => {
                rouille::Response::html(super::html::HTML_SUCCESS)
            },

            (GET) (/login) => {
                let (cc, cv) = oauth2::PkceCodeChallenge::new_random_sha256();
                *code_verify.lock().unwrap() = cv;
                rouille::Response::redirect_302(authorize_url(cc, true))
            },

            (GET) (/) => {
                let mut err = "";
                let mut code = "";
                let re = Regex::new(r"code=(.*)&state=test").unwrap();
                match re.captures(request.raw_query_string()) {
                    Some(r) => {
                        code = r.get(1).map_or("", |m| m.as_str());
                    }
                    None => {
                        err = "Bad redirect uri";
                        error!("{}", err);
                    }
                }
                if err.is_empty() {
                    let mut client = reqwest::Client::builder()
                    .redirect(reqwest::RedirectPolicy::none())
                    .build()
                    .unwrap();
                    let tokens = get_tokens(&mut client, code.to_string(), code_verify.clone());
                    if let Some(t) = tokens {
                        if !onboarded.load(std::sync::atomic::Ordering::Relaxed) {
                            std::thread::spawn(move || {
                               super::do_onboard("server.nextensio.net:8080".to_string(), t)
                            });
                            onboarded.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    } else {
                        err = "Token failure";
                    }
                }

                if err.is_empty() {
                    schan.send(super::gui::Message::LoginStatus("Logged In".to_string()));
                    rouille::Response::redirect_302("http://localhost:8180/success")
                } else {
                    schan.send(super::gui::Message::LoginStatus("Login failed, please try again".to_string()));
                    rouille::Response::html(super::html::html_error(err))
                }
            },
            _ => rouille::Response::empty_404()
        )
    });
}
