use clap::{App, Arg};
use log::error;
use nextensio::{agent_init, agent_on, onboard, CRegistrationInfo};
use pkce::refresh;
use regex::Regex;
use serde::Deserialize;
use signal_hook::{consts::SIGABRT, consts::SIGINT, consts::SIGTERM, iterator::Signals};
use std::io::Write;
use std::os::raw::{c_char, c_int};
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::{ffi::CString, usize};
use std::{fmt, time::Instant};
use uuid::Uuid;
mod pkce;

const RXMTU: u32 = 1500;
const TXMTU: u32 = 1500;

// TODO: The rouille and reqwest libs are very heavy duty ones, we just need some
// basic simple web server and a simple http client - we can use ureq for http client,
// but we do the ignore-certificate business today, or even if we dont ignore, we might
// want to specficy a custom root-CA, so the http client lib should support it. Anyways,
// this docker implementation is meant for servers, so its pbbly not that big a deal.
// But is SUCKS to see that the so called "simple" http server rouille (tiny-http) spawns
// like eight threads when we open listeners on two ports (4 threads  per port ?)

#[derive(Debug, Deserialize)]
struct Domain {
    name: String,
    needdns: bool,
    dnsip: String,
}

#[derive(Debug, Deserialize)]
struct OnboardInfo {
    Result: String,
    userid: String,
    tenant: String,
    gateway: String,
    domains: Vec<Domain>,
    services: Vec<String>,
    connectid: String,
    cluster: String,
    cacert: Vec<u8>,
    version: String,
    keepalive: usize,
}

#[derive(Debug, Deserialize)]
struct KeepaliveResponse {
    Result: String,
    version: String,
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
            write!(f, " {}:{}:{}", d.name, d.needdns, d.dnsip).ok();
        }
        Ok(())
    }
}

fn cmd(cmd: &str) -> (String, String) {
    let mut shell = Command::new("bash");
    let output = shell.arg("-c").arg(cmd).output().expect(cmd);
    let mut stdout = "".to_string();
    let mut stderr = "".to_string();
    if let Ok(s) = String::from_utf8(output.stdout) {
        stdout = s;
    }
    if let Ok(s) = String::from_utf8(output.stderr) {
        stderr = s;
    }
    return (stdout, stderr);
}

fn cleanup_iptables() {
    let (out, _) = cmd("ip rule ls");
    for o in out.lines() {
        if o != "" {
            let re = Regex::new(r"([0-9]+):.*0x3a73.*215").unwrap();
            match re.captures(&o) {
                Some(r) => {
                    let s = r.get(1).map_or("", |m| m.as_str());
                    let c = format!("ip rule del prio {}", s);
                    cmd(&c);
                }
                None => {}
            }
        }
    }

    let (out, _) = cmd("iptables -t mangle -nvL");
    for o in out.lines() {
        if o != "" {
            let re = Regex::new(r".*MARK.*set.*0x3a73.*").unwrap();
            if re.is_match(&o) {
                cmd("iptables -D PREROUTING -i eth0 -t mangle -j MARK --set-mark 14963");
                cmd("iptables -D OUTPUT -t mangle -m owner ! --gid-owner nextensioapp -j MARK --set-mark 14963");
            }
        }
    }
}

// The numbers 14963, 215 etc.. are chosen to be "random" so that
// if the user's linux already has other rules, we dont clash with
// it. Ideally we should probe and find out free numbers to use, this
// is just a poor man's solution for the time being
fn add_iptables(test: bool) {
    cmd("ip rule add fwmark 14963 table 215");
    if test {
        cmd("iptables -A PREROUTING -i eth0 -t mangle -j MARK --set-mark 14963");
    } else {
        cmd("iptables -A OUTPUT -t mangle -m owner ! --gid-owner nextensioapp -j MARK --set-mark 14963");
    }
}

fn kill_agent() {
    cmd("pkill -9 nextensio");
}

fn has_iptables() -> bool {
    let (out1, _) = cmd("which iptables");
    let (out2, _) = cmd("which ip");
    return out1 != "" && out2 != "";
}

fn has_addgroup() -> bool {
    return std::path::Path::new("/usr/sbin/addgroup").exists();
}

fn is_root() -> bool {
    let (_, err) = cmd("iptables -nvL");
    return !err.contains("denied");
}

fn config_tun(test: bool, mtu: u32) {
    cmd("ifconfig tun215 up");
    cmd("ifconfig tun215 169.254.2.1 netmask 255.255.255.0");
    cmd(&format!("ifconfig tun215 mtu {}", mtu));
    cmd(&format!(
        "ip route add default via 169.254.2.1 dev tun215 mtu {} table 215",
        mtu
    ));
    add_iptables(test);
}

fn create_tun() -> Result<i32, std::io::Error> {
    let flags: u16 = (libc::IFF_TUN | libc::IFF_NO_PI) as u16;
    let mut ifr: [u8; libc::IFNAMSIZ + 64] = [0 as u8; libc::IFNAMSIZ + 64];
    ifr[0] = 't' as u8;
    ifr[1] = 'u' as u8;
    ifr[2] = 'n' as u8;
    ifr[3] = '2' as u8;
    ifr[4] = '1' as u8;
    ifr[5] = '5' as u8;
    ifr[6] = 0;
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
        Ok(fd)
    }
}

fn agent_onboard(onb: &OnboardInfo, access_token: String, uuid: &Uuid) {
    let c_access_token = CString::new(access_token).unwrap();
    let uuid_str = format!("{}", uuid);
    let c_uuid_str = CString::new(uuid_str).unwrap();
    let c_userid = CString::new(onb.userid.clone()).unwrap();
    let c_gateway = CString::new(onb.gateway.clone()).unwrap();
    let c_connectid = CString::new(onb.connectid.clone()).unwrap();
    let c_cluster = CString::new(onb.cluster.clone()).unwrap();
    let mut c_domains: Vec<CString> = Vec::new();
    let mut c_domains_ptr: Vec<*const c_char> = Vec::new();
    for d in &onb.domains {
        let s = CString::new(d.name.clone()).unwrap();
        let p = s.as_ptr();
        c_domains.push(s);
        c_domains_ptr.push(p);
    }
    let mut c_needdns: Vec<c_int> = Vec::new();
    for d in &onb.domains {
        let s;
        if d.needdns {
            s = 1;
        } else {
            s = 0;
        }
        c_needdns.push(s);
    }
    let mut c_dnsip: Vec<CString> = Vec::new();
    let mut c_dnsip_ptr: Vec<*const c_char> = Vec::new();
    for d in &onb.domains {
        let s = CString::new(d.dnsip.clone()).unwrap();
        let p = s.as_ptr();
        c_dnsip.push(s);
        c_dnsip_ptr.push(p);
    }
    let mut c_services: Vec<CString> = Vec::new();
    let mut c_services_ptr: Vec<*const c_char> = Vec::new();
    for svc in &onb.services {
        let s = CString::new(svc.clone()).unwrap();
        let p = s.as_ptr();
        c_services.push(s);
        c_services_ptr.push(p);
    }
    let hostname = CString::new("localhost").unwrap();
    let model = CString::new("model").unwrap();
    let os_type = CString::new("linux").unwrap();
    let os_name = CString::new("linux").unwrap();
    let creg = CRegistrationInfo {
        gateway: c_gateway.as_ptr(),
        access_token: c_access_token.as_ptr(),
        connect_id: c_connectid.as_ptr(),
        cluster: c_cluster.as_ptr(),
        domains: c_domains_ptr.as_ptr() as *const *const c_char,
        needdns: c_needdns.as_ptr() as *const c_int,
        dnsip: c_dnsip_ptr.as_ptr() as *const *const c_char,
        num_domains: c_domains_ptr.len() as c_int,
        ca_cert: onb.cacert.as_ptr() as *const c_char,
        num_cacert: onb.cacert.len() as c_int,
        userid: c_userid.as_ptr(),
        uuid: c_uuid_str.as_ptr(),
        services: c_services_ptr.as_ptr() as *const *const c_char,
        num_services: c_services_ptr.len() as c_int,
        hostname: hostname.as_ptr(),
        model: model.as_ptr(),
        os_type: os_type.as_ptr(),
        os_name: os_name.as_ptr(),
        os_patch: 1,
        os_major: 10,
        os_minor: 8,
    };
    unsafe { onboard(creg) };
}

// Onboard the agent and see if there are too many tunnel flaps, in which case
// do onboarding again in case the agent parameters are changed on the controller
fn do_onboard(test: bool, controller: String, username: String, password: String) {
    let mut access_token;
    let mut refresh_token;
    let mut onboarded = false;
    let mut version = "".to_string();
    let mut force_onboard = false;
    let uuid = Uuid::new_v4();
    let mut keepalive: usize = 30;
    let mut last_keepalive = Instant::now();
    let mut refresh = Instant::now();

    // TODO: Once we start using proper certs for our production clusters, make this
    // accept_invalid_certs true only for test environment. Even test environments ideally
    // should have verifiable certs via a test.nextensio.net domain or something
    let mut ka_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    // TODO: Once we start using proper certs for our production clusters, make this
    // accept_invalid_certs true only for test environment. Even test environments ideally
    // should have verifiable certs via a test.nextensio.net domain or something
    let mut onb_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    loop {
        let token = pkce::authenticate(test, &username, &password);
        if let Some(t) = token {
            access_token = t.access_token;
            refresh_token = t.refresh_token;
            break;
        }
        error!("Cannot get access token");
        println!("Login to nextensio failed (cannot get tokens), will try again in 10 seconds");
        thread::sleep(Duration::new(10, 0));
    }

    loop {
        let now = Instant::now();
        if onboarded {
            if now > last_keepalive + Duration::from_secs(keepalive as u64) {
                force_onboard = agent_keepalive(
                    controller.clone(),
                    access_token.clone(),
                    &version,
                    &uuid,
                    &mut ka_client,
                );
                last_keepalive = now;
            }
        }
        // Okta is configured with one hour as the access token lifetime,
        // refresh at 45 minutes
        if now > refresh + Duration::from_secs(45 * 60) {
            let token = pkce::refresh(test, &refresh_token);
            if let Some(t) = token {
                access_token = t.access_token;
                refresh_token = t.refresh_token;
                refresh = now;
                // Send the new tokens to the gateway
                force_onboard = true;
                error!("Force onboard");
            } else {
                error!("Refresh token failed, will retry in 30 seconds")
            }
        }
        if !onboarded || force_onboard {
            error!("Onboarding again");
            println!("Onboarding with nextensio controller");
            let (o, onb) = okta_onboard(
                controller.clone(),
                access_token.clone(),
                &uuid,
                &mut onb_client,
            );
            if o {
                let onb = onb.unwrap();
                version = onb.version.clone();
                keepalive = onb.keepalive;
                if keepalive == 0 {
                    keepalive = 5 * 60;
                }
                onboarded = true;
                force_onboard = false;
            }
        }
        thread::sleep(Duration::from_secs(30));
    }
}

fn okta_onboard(
    controller: String,
    access_token: String,
    uuid: &Uuid,
    client: &mut reqwest::Client,
) -> (bool, Option<OnboardInfo>) {
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
                            println!("Login to nextensio failed ({}), will try again", o.Result);
                            return (false, None);
                        } else {
                            error!("Onboarded {}", o);
                            println!("Login to nextensio successful");
                            agent_onboard(&o, access_token.clone(), uuid);
                            return (true, Some(o));
                        }
                    }
                    Err(e) => {
                        error!("HTTP body failed {:?}", e);
                        println!("Login to nextensio failed ({}), will try again", e);
                        return (false, None);
                    }
                }
            } else {
                error!("HTTP Get result {}, failed", res.status());
                println!(
                    "Login to nextensio failed ({}), will try again",
                    res.status()
                );
                return (false, None);
            }
        }
        Err(e) => {
            error!("HTTP Get failed {:?}", e);
            println!("Login to nextensio failed ({}), will try again", e);
            return (false, None);
        }
    }
}

fn agent_keepalive(
    controller: String,
    access_token: String,
    version: &str,
    uuid: &Uuid,
    client: &mut reqwest::Client,
) -> bool {
    let get_url = format!(
        "https://{}/api/v1/global/get/keepalive/{}/{}",
        controller, version, uuid
    );
    let bearer = format!("Bearer {}", access_token);
    let resp = client.get(&get_url).header("Authorization", bearer).send();
    match resp {
        Ok(mut res) => {
            if res.status().is_success() {
                let keep_res: Result<KeepaliveResponse, reqwest::Error> = res.json();
                match keep_res {
                    Ok(ks) => {
                        if ks.Result != "ok" {
                            error!("Keepalive from controller not ok {}", ks.Result);
                            return false;
                        } else {
                            if version != ks.version {
                                error!("Keepalive version mismatch {}/{}", version, ks.version);
                                return true;
                            }
                            return false;
                        }
                    }
                    Err(e) => {
                        error!("Keepalive HTTP body failed {:?}", e);
                        return false;
                    }
                }
            } else {
                error!("Keepalive HTTP Get result {}, failed", res.status());
                return false;
            }
        }
        Err(e) => {
            error!("Keepalive HTTP Get failed {:?}", e);
            return false;
        }
    }
}

fn main() {
    if !has_iptables() {
        println!("Need iptables and iproute2 packages: sudo apt-install iptables iproute2");
        return;
    }
    if !has_addgroup() {
        println!("Need /usr/sbin/addgroup command: sudo apt-install addgroup");
        return;
    }
    if !is_root() {
        println!("Need to run as sudo: sudo nextensio");
        return;
    }

    let matches = App::new("NxtAgent")
        .arg(
            Arg::with_name("stop")
                .long("stop")
                .help("Disconnect from Nextensio"),
        )
        .get_matches();

    if matches.is_present("stop") {
        kill_agent();
        cleanup_iptables();
        return;
    }

    if let Ok(mut signals) = Signals::new(&[SIGINT, SIGTERM, SIGABRT]) {
        thread::spawn(move || {
            for sig in signals.forever() {
                println!("Received signal {:?}, terminating nextensio", sig);
                cleanup_iptables();
                std::process::exit(0);
            }
        });
    }

    // "test" is true if we are running in a docker container in nextensio testbed
    // Right now this same layer is used for testbed and real agent - not a lot of
    // difference between them, but at some point we might seperate out both
    let mut test = true;
    let mut found = 0;
    let mut controller = "server.nextensio.net:8080".to_string();
    let mut username = "".to_string();
    let mut password = "".to_string();

    for (key, value) in std::env::vars() {
        if key == "NXT_USERNAME" {
            username = value;
            found += 1;
        } else if key == "NXT_PWD" {
            password = value;
            found += 1;
        } else if key == "NXT_CONTROLLER" {
            controller = value;
            found += 1;
        }
    }

    if found != 3 {
        // Add a group to run this app as, this is all temporary till we
        // figure out a proper installation process on linux for these agents.
        // The 14963 is just some groupid we pick, its not related to the set-mark
        cmd("/usr/sbin/addgroup --gid 14963 nextensioapp");
        unsafe {
            let ret = libc::setgid(14963);
            if ret != 0 {
                println!(
                    "Unexpected error: Unable to move nextensio app to group nextensioapp {}",
                    ret
                );
                return;
            }
        }
        test = false;
        controller = "server.nextensio.net:8080".to_string();
        print!("Nextensio Username: ");
        std::io::stdout().flush().unwrap();
        std::io::stdin()
            .read_line(&mut username)
            .expect("Please enter a username");
        username = username.trim().to_string();
        print!("Nextensio Password: ");
        std::io::stdout().flush().unwrap();
        password = rpassword::read_password().unwrap_or(password);
        println!("Trying to login to nextensio");
    }

    if test {
        env_logger::init();
    }
    let fd = create_tun().unwrap();
    config_tun(test, RXMTU);

    thread::spawn(move || do_onboard(test, controller, username, password));

    unsafe {
        agent_on(fd);
        agent_init(0 /*platform*/, 0 /*direct*/, RXMTU, TXMTU, 1, 0);
    }
}
