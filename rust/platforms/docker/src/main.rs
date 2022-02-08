use clap::{App, Arg};
use log::error;
use nextensio::{agent_init, agent_on, agent_stats, onboard, AgentStats, CRegistrationInfo};
use regex::Regex;
use serde::{Deserialize, Serialize};
use signal_hook::{consts::SIGABRT, consts::SIGINT, consts::SIGTERM, iterator::Signals};
use std::io::Write;
use std::os::raw::{c_char, c_int};
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::{ffi::CString, usize};
use std::{fmt, time::Instant};
use uuid::Uuid;
mod gui;
mod html;
mod pkce;
use pnet::datalink;

const MTU: u32 = 1500;

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
}
#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct OnboardInfo {
    Result: String, // The json response has Caps Result, so we ignore clippy
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

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct ClientId {
    Result: String, // The json response has Caps Result, so we ignore clippy
    clientid: String,
}

#[derive(Serialize)]
struct KeepaliveRequest<'a> {
    device: &'a str,
    gateway: u32,
    version: &'a str,
    source: &'a str,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct KeepaliveResponse {
    Result: String, // The json response has Caps Result, so we ignore clippy
    version: String,
    clientid: String,
}

fn chgroup(name: &str) -> Result<(), nix::Error> {
    match nix::unistd::Group::from_name(name)? {
        Some(group) => nix::unistd::setgid(group.gid),
        None => Err(nix::Error::last()),
    }
}

fn chuser(uid: u32) -> Result<(), nix::Error> {
    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid))
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
            write!(f, " {}", d.name).ok();
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
    (stdout, stderr)
}

fn cleanup_iptables(interface: String) {
    let (out, _) = cmd("ip rule ls");
    for o in out.lines() {
        if !o.is_empty() {
            let re = Regex::new(r"([0-9]+):.*0x3a73.*215").unwrap();
            if let Some(r) = re.captures(o) {
                let s = r.get(1).map_or("", |m| m.as_str());
                let c = format!("ip rule del prio {}", s);
                cmd(&c);
            }
        }
    }

    let (out, _) = cmd("iptables -t mangle -nvL");
    for o in out.lines() {
        if !o.is_empty() {
            let re = Regex::new(r".*MARK.*set.*0x3a73.*").unwrap();
            if re.is_match(o) {
                if !interface.is_empty() {
                    let c = format!(
                        "iptables -D PREROUTING -i {} -t mangle -j MARK --set-mark 14963",
                        interface
                    );
                    cmd(&c);
                }
                cmd("iptables -D OUTPUT -t mangle -m owner ! --gid-owner nextensioapp -j MARK --set-mark 14963");
                iptables_ignore_connected_subnets(false);
            }
        }
    }
}

// This is required because if we are running inside a linux VM, the default
// dns server of that VM might be the host. So if we dont add these rules, the
// dns requests to the host will also be captured and attempt to be sent via
// the agent tunnel
fn iptables_ignore_connected_subnets(add: bool) {
    let mut iptables;
    if add {
        iptables = "iptables -A OUTPUT -t mangle -d ".to_owned();
    } else {
        iptables = "iptables -D OUTPUT -t mangle -d ".to_owned();
    }
    let mut first = true;
    for iface in datalink::interfaces() {
        for ip in iface.ips {
            if let pnet::ipnetwork::IpNetwork::V4(x) = ip {
                let ipm;
                if first {
                    ipm = format!("{}/{}", x.ip(), x.prefix());
                } else {
                    ipm = format!(",{}/{}", x.ip(), x.prefix());
                }
                first = false;
                iptables.push_str(&ipm);
            }
        }
    }
    iptables.push_str(" -j RETURN");
    cmd(&iptables);
}

// The numbers 14963, 215 etc.. are chosen to be "random" so that
// if the user's linux already has other rules, we dont clash with
// it. Ideally we should probe and find out free numbers to use, this
// is just a poor man's solution for the time being
fn add_iptables(interface: &str) {
    cmd("ip rule add fwmark 14963 table 215");
    if !interface.is_empty() {
        let c = format!(
            "iptables -A PREROUTING -i {} -t mangle -j MARK --set-mark 14963",
            interface
        );
        cmd(&c);
    } else {
        iptables_ignore_connected_subnets(true);
        cmd("iptables -A OUTPUT -t mangle -m owner ! --gid-owner nextensioapp -j MARK --set-mark 14963");
    }
}

fn kill_agent() {
    cmd("pkill -9 nextensio");
}

fn has_iptables() -> bool {
    let (out1, _) = cmd("which iptables");
    let (out2, _) = cmd("which ip");
    !out1.is_empty() && !out2.is_empty()
}

fn has_addgroup() -> bool {
    std::path::Path::new("/usr/sbin/addgroup").exists()
}

fn is_root() -> bool {
    let (_, err) = cmd("iptables -nvL");
    !err.contains("denied")
}

fn config_tun(interface: &str, mtu: u32) {
    cmd("ifconfig tun215 up");
    cmd("ifconfig tun215 169.254.2.1 netmask 255.255.255.0");
    cmd(&format!("ifconfig tun215 mtu {}", mtu));
    cmd(&format!(
        "ip route add default via 169.254.2.1 dev tun215 mtu {} table 215",
        mtu
    ));
    cmd("echo 0 > /proc/sys/net/ipv4/conf/tun215/rp_filter");
    cmd("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter");
    add_iptables(interface);
}

fn create_tun() -> Result<i32, std::io::Error> {
    let flags: u16 = (libc::IFF_TUN | libc::IFF_NO_PI) as u16;
    let mut ifr: [u8; libc::IFNAMSIZ + 64] = [0_u8; libc::IFNAMSIZ + 64];
    ifr[0] = b't';
    ifr[1] = b'u';
    ifr[2] = b'n';
    ifr[3] = b'2';
    ifr[4] = b'1';
    ifr[5] = b'5';
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
fn do_onboard(mut client_id: String, controller: String, tokens: pkce::AccessIdTokens) {
    let mut access_token = tokens.access_token;
    let mut refresh_token = tokens.refresh_token;
    let mut onboarded = false;
    let mut version = "".to_string();
    let mut force_onboard = false;
    let uuid = Uuid::new_v4();
    let mut keepalive: usize = 30;
    let mut last_keepalive = Instant::now();
    let mut refresh = Instant::now();
    let mut keepalivecount = 0;
    let mut public_ip = "".to_string();

    let mut hostname = "linux_unknown".to_string();
    if let Ok(h) = gethostname::gethostname().into_string() {
        hostname = h;
    }

    let mut ka_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(is_test_mode())
        .build()
        .unwrap();
    let mut onb_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(is_test_mode())
        .build()
        .unwrap();

    loop {
        let now = Instant::now();
        if onboarded && now > last_keepalive + Duration::from_secs(keepalive as u64) {
            if (keepalivecount % 4) == 0 {
                let p = get_public_ip();
                if !p.is_empty() {
                    public_ip = p;
                }
            }
            keepalivecount += 1;
            let (force, cid) = agent_keepalive(
                controller.clone(),
                access_token.clone(),
                &version,
                &mut ka_client,
                &public_ip,
                &hostname,
            );
            force_onboard = force;
            if let Some(c) = cid {
                // If clientid changes while users are connected, this will ensure users will
                // have minimal impact, the next keepalive will restore sanity, otherwise we
                // will have to call them up on phone and ask them to restart the agent etc..
                if !c.is_empty() {
                    client_id = c;
                }
            }
            last_keepalive = now;
        }
        // Okta is configured with one hour as the access token lifetime,
        // refresh at 45 minutes
        if now > refresh + Duration::from_secs(45 * 60) {
            let token = pkce::refresh(&client_id, &refresh_token);
            if let Some(t) = token {
                access_token = t.access_token;
                refresh_token = t.refresh_token;
                refresh = now;
                error!("Force onboard");
            } else {
                error!("Refresh token failed, will retry in 30 seconds");
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
                            (false, None)
                        } else {
                            error!("Onboarded {}", o);
                            println!("Login to nextensio successful");
                            agent_onboard(&o, access_token, uuid);
                            (true, Some(o))
                        }
                    }
                    Err(e) => {
                        error!("HTTP body failed {:?}", e);
                        println!("Login to nextensio failed ({}), will try again", e);
                        (false, None)
                    }
                }
            } else {
                error!("HTTP Get result {}, failed", res.status());
                println!(
                    "Login to nextensio failed ({}), will try again",
                    res.status()
                );
                (false, None)
            }
        }
        Err(e) => {
            error!("HTTP Get failed {:?}", e);
            println!("Login to nextensio failed ({}), will try again", e);
            (false, None)
        }
    }
}

fn get_public_ip() -> String {
    if let Ok(client) = reqwest::Client::builder().build() {
        let resp = client.get("https://api.ipify.org").send();
        if let Ok(mut res) = resp {
            if res.status().is_success() {
                if let Ok(t) = res.text() {
                    return t;
                }
            }
        }
    }
    "".to_string()
}

fn agent_keepalive(
    controller: String,
    access_token: String,
    version: &str,
    client: &mut reqwest::Client,
    public_ip: &str,
    hostname: &str,
) -> (bool, Option<String>) {
    let mut stats = AgentStats::default();
    unsafe { agent_stats(&mut stats) };
    let details = KeepaliveRequest {
        gateway: stats.gateway_ip,
        device: hostname,
        version,
        source: public_ip,
    };
    let j = serde_json::to_string(&details).unwrap();
    let post_url = format!("https://{}/api/v1/global/add/keepaliverequest", controller);
    let bearer = format!("Bearer {}", access_token);
    let resp = client
        .post(&post_url)
        .body(j)
        .header("Authorization", bearer)
        .send();
    match resp {
        Ok(mut res) => {
            if res.status().is_success() {
                let keep_res: Result<KeepaliveResponse, reqwest::Error> = res.json();
                match keep_res {
                    Ok(ks) => {
                        if ks.Result != "ok" {
                            error!("Keepalive from controller not ok {}", ks.Result);
                            (false, None)
                        } else if version != ks.version {
                            error!("Keepalive version mismatch {}/{}", version, ks.version);
                            (true, Some(ks.clientid))
                        } else {
                            (false, Some(ks.clientid))
                        }
                    }
                    Err(e) => {
                        error!("Keepalive HTTP body failed {:?}", e);
                        (false, None)
                    }
                }
            } else {
                error!("Keepalive HTTP Get result {}, failed", res.status());
                (false, None)
            }
        }
        Err(e) => {
            error!("Keepalive HTTP Get failed {:?}", e);
            (false, None)
        }
    }
}

fn is_test_mode() -> bool {
    std::env::var("NXT_TESTING").is_ok()
}

fn okta_clientid(controller: &str, client: &mut reqwest::Client) -> String {
    let get_url = format!(
        "https://{}/api/v1/global/get/clientid/09876432087648932147823456123768",
        controller
    );
    let resp = client.get(&get_url).send();
    match resp {
        Ok(mut res) => {
            if res.status().is_success() {
                let onb: Result<ClientId, reqwest::Error> = res.json();
                match onb {
                    Ok(o) => {
                        if o.Result != "ok" {
                            error!("Clientid: Result from controller not ok {}", o.Result);
                            println!("Clientid get failed ({}), will try again", o.Result);
                            "".to_string()
                        } else {
                            o.clientid
                        }
                    }
                    Err(e) => {
                        error!("Clientid: HTTP body failed {:?}", e);
                        println!("Clientid get  failed ({}), will try again", e);
                        "".to_string()
                    }
                }
            } else {
                error!("Clientid: HTTP Get result {}, failed", res.status());
                println!("Clientid get failed ({}), will try again", res.status());
                "".to_string()
            }
        }
        Err(e) => {
            error!("HTTP Get failed {:?}", e);
            println!("Login to nextensio failed ({}), will try again", e);
            "".to_string()
        }
    }
}

fn get_idp() -> String {
    if let Ok(nxtidp) = std::env::var("NXT_IDP") {
        nxtidp
    } else {
        "login.nextensio.net".to_string()
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
        println!("Need to run as sudo (for adding iptable mangle rule): \"sudo nextensio\"");
        return;
    }

    // "test" is true if we are running in a docker container in nextensio testbed
    // Right now this same layer is used for testbed and real agent - not a lot of
    // difference between them, but at some point we might seperate out both
    let mut interface = "".to_string();
    let mut controller = "server.nextensio.net:8080".to_string();
    let mut username = "".to_string();
    let mut password = "".to_string();

    for (key, value) in std::env::vars() {
        if key == "NXT_USERNAME" {
            username = value;
        } else if key == "NXT_PWD" {
            password = value;
        } else if key == "NXT_CONTROLLER" {
            controller = value;
        } else if key == "NXT_INTERFACE" {
            interface = value;
        }
    }

    if is_test_mode() && interface.is_empty() {
        interface = "eth0".to_string();
    }

    let matches = App::new("NxtAgent")
        .arg(
            Arg::with_name("stop")
                .long("stop")
                .help("Disconnect from Nextensio"),
        )
        .arg(
            Arg::with_name("text-only")
                .long("text-only")
                .help("Text based login"),
        )
        .get_matches();

    if matches.is_present("stop") {
        kill_agent();
        cleanup_iptables(interface);
        return;
    }
    let mut text_only = false;
    if matches.is_present("text-only") {
        text_only = true;
    }

    if let Ok(mut signals) = Signals::new(&[SIGINT, SIGTERM, SIGABRT]) {
        let intf = interface.clone();
        thread::spawn(move || {
            for sig in signals.forever() {
                println!("Received signal {:?}, terminating nextensio", sig);
                cleanup_iptables(intf);
                std::process::exit(0);
            }
        });
    }

    let mut uid: u32 = 0;

    if !is_test_mode() {
        cmd("/usr/sbin/addgroup --gid 14963 nextensioapp");
        if chgroup("nextensioapp").is_err() {
            println!("Unable to change group of the client to nextensioapp, exiting");
            return;
        }
        if let Ok(uid_str) = std::env::var("SUDO_UID") {
            if let Ok(u) = uid_str.parse::<u32>() {
                uid = u;
            } else {
                println!("Unable to parse uid {}, exiting", uid_str);
                return;
            }
        } else {
            println!("Unable to get userid (uid), exiting");
            return;
        }

        controller = "server.nextensio.net:8080".to_string();
        if text_only && (username.is_empty() || password.is_empty()) {
            print!("Nextensio Username: ");
            std::io::stdout().flush().unwrap();
            std::io::stdin()
                .read_line(&mut username)
                .expect("Please enter a username");
            username = username.trim().to_string();
            print!("Nextensio Password: ");
            std::io::stdout().flush().unwrap();
            password = rpassword::read_password().unwrap_or(password);
        }
        println!("Trying to login to nextensio");
    }

    env_logger::init();
    let fd = create_tun().unwrap();
    config_tun(&interface, MTU);

    if uid != 0 && chuser(uid).is_err() {
        println!("Unable to drop privileges to uid {}, exiting", uid);
        cleanup_iptables(interface);
        return;
    }

    unsafe {
        agent_on(fd);
        thread::spawn(move || agent_init(0 /*platform*/, 0 /*direct*/, MTU, 1, 0));
    }

    if !is_test_mode() && (username.is_empty() || password.is_empty()) {
        gui::gui_main(controller);
        cleanup_iptables(interface);
        std::process::exit(0);
    } else {
        let mut client = reqwest::Client::builder()
            .redirect(reqwest::RedirectPolicy::none())
            .danger_accept_invalid_certs(is_test_mode())
            .build()
            .unwrap();
        loop {
            let client_id = okta_clientid(&controller, &mut client);
            let token = pkce::authenticate(&client_id, &mut client, &username, &password);
            if let Some(t) = token {
                thread::spawn(move || do_onboard(client_id, controller, t));
                break;
            } else {
                error!("Login to nextensio failed");
                println!("Login to nextensio failed");
                error!("Retrying after 5 seconds");
                println!("Retrying after 5 seconds");
                thread::sleep(std::time::Duration::from_secs(5));
            }
        }
        loop {
            thread::sleep(std::time::Duration::from_secs(5));
        }
    }
}
