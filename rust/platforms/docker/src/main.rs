use clap::{App, Arg};
use log::error;
use nextensio::{agent_init, agent_on, agent_stats, onboard, AgentStats, CRegistrationInfo};
use serde::Deserialize;
use std::ffi::CString;
use std::fmt;
use std::os::raw::{c_char, c_int};
use std::process::Command;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

const MAXBUF: usize = 64 * 1024;

// TODO: The rouille and reqwest libs are very heavy duty ones, we just need some
// basic simple web server and a simple http client - we can use ureq for http client,
// but we do the ignore-certificate business today, or even if we dont ignore, we might
// want to specficy a custom root-CA, so the http client lib should support it. Anyways,
// this docker implementation is meant for servers, so its pbbly not that big a deal.
// But is SUCKS to see that the so called "simple" http server rouille (tiny-http) spawns
// like eight threads when we open listeners on two ports (4 threads  per port ?)

#[derive(Debug, Deserialize)]
struct OnboardInfo {
    Result: String,
    userid: String,
    tenant: String,
    gateway: String,
    domains: Vec<String>,
    services: Vec<String>,
    connectid: String,
    cacert: Vec<u8>,
}

impl fmt::Display for OnboardInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "userid: {}, tenant: {}, gateway: {}, connectid: {}",
            self.userid, self.tenant, self.gateway, self.connectid
        )
        .ok();
        for d in self.domains.iter() {
            write!(f, " {}", d).ok();
        }
        Ok(())
    }
}

fn cmd(cmd: &str) {
    let mut shell = Command::new("bash");
    shell.arg("-c").arg(cmd).output().expect(cmd);
}

// The files/run.sh will create a route table named nxt and add
// some rules to mark packets in that table etc.. BEFORe the agent runs
fn config_tun(mtu: usize) {
    cmd("ifconfig tun0 up");
    cmd("ifconfig tun0 169.254.2.1 netmask 255.255.255.0");
    cmd(&format!("ifconfig tun0 mtu {}", mtu));
    cmd(&format!(
        "ip route add default via 169.254.2.1 dev tun0 mtu {} table nxt",
        mtu
    ));
}

fn create_tun() -> Result<i32, std::io::Error> {
    let flags: u16 = (libc::IFF_TUN | libc::IFF_NO_PI) as u16;
    let mut ifr: [u8; libc::IFNAMSIZ + 64] = [0 as u8; libc::IFNAMSIZ + 64];
    ifr[0] = 't' as u8;
    ifr[1] = 'u' as u8;
    ifr[2] = 'n' as u8;
    ifr[3] = '0' as u8;
    ifr[4] = 0;
    ifr[libc::IFNAMSIZ] = (flags & 0xFF) as u8;
    ifr[libc::IFNAMSIZ + 1] = ((flags & 0xFF00) >> 8) as u8;
    unsafe {
        let fd = libc::open(
            CString::new("/dev/net/tun").unwrap().as_c_str().as_ptr(),
            libc::O_RDWR,
        );
        let old = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, old | libc::O_NONBLOCK);
        let rc = libc::ioctl(fd, 1074025674, ifr.as_mut_ptr());
        error!("FD {} RC {}", fd, rc);
        println!("FD {} RC {}", fd, rc);
        Ok(fd)
    }
}

fn agent_onboard(onb: &OnboardInfo, access_token: String) {
    let c_access_token = CString::new(access_token).unwrap();
    let uuid = Uuid::new_v4();
    let uuid_str = format!("{}", uuid);
    let c_uuid_str = CString::new(uuid_str).unwrap();
    let c_userid = CString::new(onb.userid.clone()).unwrap();
    let c_host = CString::new(onb.gateway.clone()).unwrap();
    let c_connectid = CString::new(onb.connectid.clone()).unwrap();
    let mut c_domains: Vec<CString> = Vec::new();
    let mut c_domains_ptr: Vec<*const c_char> = Vec::new();
    for d in &onb.domains {
        let s = CString::new(d.clone()).unwrap();
        let p = s.as_ptr();
        c_domains.push(s);
        c_domains_ptr.push(p);
    }
    let mut c_services: Vec<CString> = Vec::new();
    let mut c_services_ptr: Vec<*const c_char> = Vec::new();
    for svc in &onb.services {
        let s = CString::new(svc.clone()).unwrap();
        let p = s.as_ptr();
        c_services.push(s);
        c_services_ptr.push(p);
    }
    c_services.push(CString::new("foobar").unwrap());
    let creg = CRegistrationInfo {
        host: c_host.as_ptr(),
        access_token: c_access_token.as_ptr(),
        connect_id: c_connectid.as_ptr(),
        domains: c_domains_ptr.as_ptr() as *const *const c_char,
        num_domains: c_domains_ptr.len() as c_int,
        ca_cert: onb.cacert.as_ptr() as *const c_char,
        num_cacert: onb.cacert.len() as c_int,
        userid: c_userid.as_ptr(),
        uuid: c_uuid_str.as_ptr(),
        services: c_services_ptr.as_ptr() as *const *const c_char,
        num_services: c_services_ptr.len() as c_int,
    };
    unsafe { onboard(creg) };
}

// Onboard the agent and see if there are too many tunnel flaps, in which case
// do onboarding again in case the agent parameters are changed on the controller
fn do_onboard(controller: String, username: String, password: String) {
    okta_onboard(controller.clone(), username.clone(), password.clone());
    let mut stats = AgentStats::default();
    let mut gateway_flaps = 0;
    loop {
        unsafe {
            agent_stats(&mut stats);
        }
        if stats.gateway_flaps - gateway_flaps >= 3 {
            error!("Onboarding again");
            okta_onboard(controller.clone(), username.clone(), password.clone());
        }
        gateway_flaps = stats.gateway_flaps;
        thread::sleep(Duration::new(10, 0));
    }
}

// Gaah.. We need to rewrite this pkce.go in rust.
// Taking the lazy route at the moment and just using the go version
fn get_token(username: &str, password: &str) -> Option<String> {
    let out = Command::new("/rust/files/pkce")
        .arg("https://dev-635657.okta.com")
        .arg(username)
        .arg(password)
        .output();
    if let Ok(token) = out {
        match token.status.code() {
            Some(code) => {
                if code == 0 {
                    return Some(String::from_utf8_lossy(&token.stdout).trim().to_string());
                }
            }
            _ => (),
        }
    }
    return None;
}
fn okta_onboard(controller: String, username: String, password: String) {
    let token = get_token(&username, &password);
    if token.is_none() {
        error!("Cannot get access token");
        return;
    }
    let access_token = token.unwrap();
    // TODO: Once we start using proper certs for our production clusters, make this
    // accept_invalid_certs true only for test environment. Even test environments ideally
    // should have verifiable certs via a test.nextensio.net domain or something
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let get_url = format!("https://{}/api/v1/global/get/onboard", controller);
    let bearer = format!("Bearer {}", access_token);
    let resp = client.get(&get_url).header("Authorization", bearer).send();
    match resp {
        Ok(mut res) => {
            if res.status().is_success() {
                let onb: Result<OnboardInfo, reqwest::Error> = res.json();
                match onb {
                    Ok(o) => {
                        if o.Result != "ok" {
                            error!("Result from controller not ok {}", o.Result);
                        } else {
                            error!("Onboarded {}", o);
                            agent_onboard(&o, access_token.clone());
                        }
                    }
                    Err(e) => {
                        error!("HTTP body failed {:?}", e);
                    }
                }
            } else {
                error!("HTTP Get result {}, failed", res.status());
            }
        }
        Err(e) => {
            error!("HTTP Get failed {:?}", e);
        }
    }
}

fn main() {
    stderrlog::new().module(module_path!()).init().unwrap();
    let matches = App::new("NxtAgent")
        .arg(
            Arg::with_name("controller")
                .long("controller")
                .takes_value(true)
                .help("Controller FQDN/ip address"),
        )
        .arg(
            Arg::with_name("username")
                .long("username")
                .takes_value(true)
                .help("User Id"),
        )
        .arg(
            Arg::with_name("password")
                .long("password")
                .takes_value(true)
                .help("Password"),
        )
        .get_matches();

    let controller = matches
        .value_of("controller")
        .unwrap_or("server.nextensio.net:8080")
        .to_owned();
    let username = matches.value_of("username").unwrap_or("").to_owned();
    let password = matches.value_of("password").unwrap_or("").to_owned();

    error!("controller {}", controller);

    let fd = create_tun().unwrap();
    config_tun(MAXBUF - 1);

    thread::spawn(move || do_onboard(controller, username, password));

    unsafe {
        agent_on(fd);
        agent_init(0 /*platform*/, 0 /*direct*/, MAXBUF);
    }
}
