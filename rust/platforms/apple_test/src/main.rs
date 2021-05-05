use nextensio::{agent_init, agent_on};
use std::process::Command;

extern "C" {
    fn open_utun(num: u64) -> i32;
}

fn cmd(cmd: &str) {
    let mut shell = Command::new("bash");
    shell.arg("-c").arg(cmd).output().expect(cmd);
}

fn config_tun(tun: usize) {
    let c = format!("ifconfig utun{} 169.254.2.1 169.254.2.2 up", tun);
    cmd(&c);
}

fn get_utun() -> Option<i32> {
    for utun_n in 0..255 {
        let fd = unsafe { open_utun(utun_n) };
        if fd >= 0 {
            config_tun(utun_n as usize);
            return Some(fd);
        }
    }
    None
}

fn main() {
    let fd = get_utun().unwrap();

    unsafe {
        agent_on(fd);
        // Set MAXBUF size to 2048*3
        agent_init(1 /*platform*/, 1 /*direct*/, 2048*3, 24);
    }
}
