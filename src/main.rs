extern crate tor_config;

include!(concat!(env!("OUT_DIR"), "/version.rs"))

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let config = tor_config::load_config()!;
    info!(target: "base", "Rusty Onion v{} ({}) starting.", VERSION, short_sha());
}
