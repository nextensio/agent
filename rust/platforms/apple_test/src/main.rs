use nextensio::{agent_init, agent_on};

extern "C" {
    fn open_utun(num: u64) -> i32;
}

fn get_utun() -> Option<i32> {
    for utun_n in 0..255 {
        let fd = unsafe { open_utun(utun_n) };
        if fd >= 0 {
            return Some(fd);
        }
    }
    None
}

fn main() {
    let fd = get_utun().unwrap();

    unsafe {
        agent_on(fd);
        agent_init(1 /*platform*/, 1 /*direct*/);
    }
}
