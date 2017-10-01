extern crate authority;
#[macro_use]
extern crate log;
extern crate router_info;
extern crate tor_config;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

use authority::AuthorityDatabase;
use router_info::RouterDatabase;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let config = tor_config::load_config().unwrap();
    info!(target:"base","Rusty Onion v{} ({}) starting.",VERSION,short_sha());
    let routerdb = RouterDatabase::new(&config);
    info!(target:"base","Fetched consensus with {} routers", routerdb.count());
}
