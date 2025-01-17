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
    client: &mut reqwest::blocking::Client,
    username: &str,
    password: &str,
) -> Option<SessionToken> {
    let idp = super::get_idp();

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
        Ok(res) => {
            let status = res.status();
            if status.is_success() {
                let stoken: std::result::Result<SessionToken, reqwest::Error> = res.json();
                match stoken {
                    Ok(t) => {
                        return Some(t);
                    }
                    Err(e) => {
                        error!("HTTP authn body failed {:?}", e);
                        println!(
                            "Authentication failed ({}), please check username/password",
                            status
                        )
                    }
                }
            } else {
                error!("HTTP authn result {}, failed", status);
                println!(
                    "Authentication failed ({}), please check username/password",
                    status
                )
            }
        }
        Err(e) => {
            error!("HTTP authn failed {:?}", e);
        }
    }

    None
}

fn authorize_url(
    client_id: &str,
    code_challenge: oauth2::PkceCodeChallenge,
    prompt: bool,
) -> String {
    let idp = super::get_idp();
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

fn authorize(
    client_id: &str,
    client: &mut reqwest::blocking::Client,
    t: SessionToken,
) -> (String, oauth2::PkceCodeVerifier) {
    let (code_challenge, code_verify) = oauth2::PkceCodeChallenge::new_random_sha256();
    let auth_url = format!(
        "{}&sessionToken={}",
        authorize_url(client_id, code_challenge, false),
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
    client_id: &str,
    client: &mut reqwest::blocking::Client,
    code: String,
    code_verify: Arc<Mutex<oauth2::PkceCodeVerifier>>,
) -> Option<AccessIdTokens> {
    let idp = super::get_idp();
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
        Ok(res) => {
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

pub fn authenticate(
    client_id: &str,
    client: &mut reqwest::blocking::Client,
    username: &str,
    password: &str,
) -> Option<AccessIdTokens> {
    if let Some(t) = authn_username_pwd(client, username, password) {
        let (code, code_verifier) = authorize(client_id, client, t);
        if code.is_empty() {
            return None;
        }
        return get_tokens(client_id, client, code, Arc::new(Mutex::new(code_verifier)));
    }
    None
}

pub fn refresh(
    client: &mut reqwest::blocking::Client,
    client_id: &str,
    refresh: &str,
) -> Option<AccessIdTokens> {
    let idp = super::get_idp();

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
        Ok(res) => {
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

pub fn web_server(controller: String, schan: fltk::app::Sender<super::gui::Message>) {
    let onboarded = std::sync::atomic::AtomicBool::new(false);
    let (_, cv) = oauth2::PkceCodeChallenge::new_random_sha256();
    // The Arc<Mutex<>> stuff is needed here because these entities are shared
    // from calls to localhost::/login and callback with code to localhost::/?code=...
    // So we need to save state across these different events in time, and putting
    // this inside rouille::start_server doesnt seem to retain state, I guess rouille
    // might be dispatching multiple threads for different callbacks
    let code_verify = Arc::new(Mutex::new(cv));
    let client_id = Arc::new(Mutex::new("".to_string()));

    rouille::start_server("localhost:8180", move |request| {
        router!(request,
            (GET) (/success) => {
                rouille::Response::html(super::html::HTML_SUCCESS)
            },

            (GET) (/login) => {
                let mut client = reqwest::blocking::Client::builder()
                .pool_idle_timeout(Some(std::time::Duration::new(30, 0)))
                .pool_max_idle_per_host(2)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
                *client_id.lock().unwrap() = super::okta_clientid(&controller, &mut client);
                let (cc, cv) = oauth2::PkceCodeChallenge::new_random_sha256();
                *code_verify.lock().unwrap() = cv;
                rouille::Response::redirect_302(authorize_url(&client_id.lock().unwrap(), cc, true))
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
                    let mut client = reqwest::blocking::Client::builder()
                    .pool_idle_timeout(Some(std::time::Duration::new(30, 0)))
                    .pool_max_idle_per_host(2)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap();
                    let tokens = get_tokens(&client_id.lock().unwrap(), &mut client, code.to_string(), code_verify.clone());
                    if let Some(t) = tokens {
                        if !onboarded.load(std::sync::atomic::Ordering::Relaxed) {
                            let cid = client_id.lock().unwrap().to_owned();
                            std::thread::spawn(move || {
                               super::do_onboard(client, cid, "server.nextensio.net:8080".to_string(), t)
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
