use nextensio::{agent_init, agent_on};
use rouille::{router, Response};
use serde::Deserialize;
use std::ffi::CString;
use std::fmt;
use std::process::Command;
use std::{sync::atomic::AtomicBool, thread};

const TUNSETIFF: u64 = 1074025674;
const NXT_OKTA_RESULTS: usize = 8081;
const NXT_OKTA_LOGIN: usize = 8180;
static ONBOARDED: AtomicBool = AtomicBool::new(false);

#[derive(Deserialize)]
struct OnboardInfo {
    Result: String,
    userid: String,
    tenant: String,
    gateway: String,
    domains: Vec<String>,
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
fn config_tun() {
    cmd("ifconfig tun0 up");
    cmd("ifconfig tun0 169.254.2.1 netmask 255.255.255.0");
    cmd("iptables -A PREROUTING -i eth0 -t mangle -j MARK --set-mark 1");
    cmd("echo 201 nxt >> /etc/iproute2/rt_tables");
    cmd("ip rule add fwmark 1 table nxt");
    cmd("ip route add default via 169.254.2.1 dev tun0 table nxt");
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
        let rc = libc::ioctl(fd, TUNSETIFF, ifr.as_mut_ptr());
        println!("FD {} RC {}", fd, rc);
        Ok(fd)
    }
}

fn login_page() -> rouille::Response {
    let mut response = Response::html(login::LOGIN);
    response.status_code = 200;
    response
        .headers
        .push(("Access-Control-Allow-Origin".into(), "*".into()));
    response
}

fn onboard_status() -> rouille::Response {
    if ONBOARDED.load(std::sync::atomic::Ordering::Relaxed) == false {
        let mut response = Response::text("");
        response.status_code = 201;
        response
    } else {
        let mut response = Response::text("");
        response.status_code = 200;
        response
    }
}

fn okta_login() {
    rouille::start_server(format!("localhost:{}", NXT_OKTA_LOGIN), move |request| {
        router!(request,
            (GET) (/) => {
                login_page()
            },
            (HEAD) (/) => {
                login_page()
            },
            (GET) (/onboardstatus) => {
                onboard_status()
            },
            (HEAD) (/onboardstatus) => {
                onboard_status()
            },
            _ => {
                println!("Nonexistant path: {:?}", request);
                rouille::Response::empty_404()
            },
        )
    });
}

fn okta_results(controller: String, services: String) {
    rouille::start_server(format!("localhost:{}", NXT_OKTA_RESULTS), move |request| {
        router!(request,
            (GET) (/accessid/{access: String}/{id: String}) => {
                // TODO: Once we start using proper certs for our production clusters, make this
                // accept_invalid_certs true only for test environment. Even test environments ideally
                // should have verifiable certs via a test.nextensio.net domain or something
                let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
                let get_url = format!("https://{}/api/v1/onboard/{}", controller, access);
                let bearer = format!("Bearer {}", access);
                let resp = client.get(&get_url).header("Authorization", bearer).send();
                match resp {
                    Ok(mut res) => {
                        if res.status().is_success() {
                            let onb: Result<OnboardInfo, reqwest::Error> = res.json();
                            match onb {
                                Ok(o) => {
                                    if o.Result != "ok" {
                                        println!("Result from controller not ok {}", o.Result);
                                    } else {
                                        println!("Onboarded {}", o);
                                        ONBOARDED.store(true, std::sync::atomic::Ordering::Relaxed);
                                    }
                                },
                                Err(e) => {println!("HTTP body failed {:?}", e);},
                            }
                        } else {
                            println!("HTTP Get result {}, failed", res.status());
                        }
                    },
                    Err(e) => {println!("HTTP Get failed {:?}", e);},
                }


                let mut response = Response::text("");
                response.status_code = 200;
                response.headers.push(("Access-Control-Allow-Origin".into(), "*".into()));
                response
            },
            _ => rouille::Response::empty_404(),
        )
    });
}

fn main() {
    let fd = create_tun().unwrap();
    config_tun();

    let controller = "172.18.0.2:8080";

    thread::spawn(move || okta_login());
    thread::spawn(move || okta_results(controller.to_string(), "".to_string()));

    unsafe {
        agent_on(fd);
        agent_init(0 /*platform*/, 1 /*direct*/);
    }
}

mod login;
