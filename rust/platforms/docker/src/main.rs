use nextensio::{agent_init, agent_on};
use rouille::{router, Response};
use std::ffi::CString;
use std::process::Command;
use std::{sync::atomic::AtomicI32, thread};

const TUNSETIFF: u64 = 1074025674;
const NXT_OKTA_RESULTS: usize = 8081;
const NXT_OKTA_LOGIN: usize = 8180;
const onboarded: AtomicI32 = AtomicI32::new(0);

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

fn okta_login() {
    rouille::start_server(format!("localhost:{}", NXT_OKTA_LOGIN), move |request| {
        router!(request,
            (GET) (/) => {
                println!("Hit login root");
                let mut response = Response::html(login::LOGIN);
                response.status_code = 200;
                response.headers.push(("Access-Control-Allow-Origin".into(), "*".into()));
                response
            },
            (GET) (/onboardstatus) => {
                println!("Hit login check");
                if onboarded.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                    let mut response = Response::text("");
                    response.status_code = 201;
                    response
                } else {
                    let mut response = Response::text("");
                    response.status_code = 200;
                    response
                }
            },
            _ => rouille::Response::empty_404(),
        )
    });
}

fn okta_results() {
    rouille::start_server(format!("localhost:{}", NXT_OKTA_RESULTS), move |request| {
        router!(request,
            (GET) (/accessid/{access: String}/{id: String}) => {
                println!("Access token {}, id token {}", access, id);
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

    thread::spawn(move || okta_login());
    thread::spawn(move || okta_results());

    unsafe {
        agent_on(fd);
        agent_init(0 /*direct*/, 0 /*platform*/);
    }
}

mod login;
