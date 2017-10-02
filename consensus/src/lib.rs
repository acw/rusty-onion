extern crate chrono;
#[macro_use]
extern crate fetch;
extern crate flate2;
extern crate futures;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate nom;
extern crate parsing_utils;
extern crate ring;
extern crate tor_config;
extern crate tokio_core;

mod types;
mod parser;

pub use types::{Consensus,ConsensusParseErr,DirectorySignature,SignatureAlgorithm};

use fetch::{FetchErrors,new_core};
use flate2::write::ZlibDecoder;
use futures::{Future,Stream};
use futures::future::Either;
use hyper::Client;
use parser::parse_consensus;
use std::net::Ipv4Addr;
use std::io::Write;
use std::time::Duration;
use tokio_core::reactor::Timeout;

pub fn fetch_consensus(addr: Ipv4Addr, port: u16)
    -> Result<(Consensus, Vec<DirectorySignature>, Vec<u8>),
              FetchErrors<ConsensusParseErr>>
{
    let mut core   = new_core();
    let     handle = &core.handle();

    let uri = {
        let url = format!("http://{}:{}/tor/status-vote/current/consensus.z",
                          addr, port);
        info!(target: "consensus", "Fetching consensus data from {}", url);
        match url.parse() {
            Err(e) => {
                error!(target: "consensus",
                       "Couldn't parse consensus URL ({}): {}", url, e);
                return Err(FetchErrors::BadURL);
            }
            Ok(v) => v
        }
    };
    let get_consensus = fetch_and_parse!(handle, uri, 20, parse_consensus);

    core.run(get_consensus)
}


#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Read;
    use std::str;
    use super::*;

    #[test]
    fn can_parse_items() {
        for entry in fs::read_dir("test/").unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().into_string().unwrap().starts_with("cons") {
                let mut fd = File::open(entry.path()).unwrap();
                let mut buffer = Vec::new();
                fd.read_to_end(&mut buffer).unwrap();
                match parse_consensus(&buffer) {
                    Ok(_) => { },
                    Err(e) => {
                        println!("Parse error: {:?}", e);
                        assert!(false);
                    }
                }
            }
        }
    }
}
