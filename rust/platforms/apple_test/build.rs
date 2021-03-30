use cc;

fn main() {
    if cfg!(target_os = "macos") {
        cc::Build::new().file("src/utun.c").compile("utun");
    }
}
