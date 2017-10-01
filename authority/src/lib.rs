extern crate base64;
extern crate chrono;
#[macro_use]
extern crate fetch;
extern crate flate2;
extern crate futures;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate nom;
extern crate parsing_utils;
extern crate rand;
extern crate ring;
extern crate simple_rsa;
extern crate tokio_core;

mod parser;
pub mod types;
mod default;

use default::{DefaultAuthority, DEFAULT_AUTHORITIES};
use parser::parse_authority_keys;
use types::*;
use flate2::write::ZlibDecoder;
use futures::{Future,Stream};
use futures::future::{Either,join_all};
use hyper::Client;
use rand::Rng;
use rand::os::OsRng;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio_core::reactor::Timeout;
use fetch::*;

pub struct AuthorityDatabase {
    contents: Vec<Authority>,
    rng:      OsRng
}

impl AuthorityDatabase {
    pub fn new() -> AuthorityDatabase {
        match OsRng::new() {
            Ok(myrng) =>
                AuthorityDatabase {
                    contents: initial_authorities(),
                    rng: myrng
                },
            Err(e) =>
                panic!("Couldn't allocate OS RNG: {:?}", e)
        }
    }

    pub fn random_authority(&mut self) -> &Authority {
        match self.rng.choose(&self.contents) {
            None =>
                panic!("Authority selection before new()?"),
            Some(v) =>
                v
        }
    }

    pub fn authority_from_fingerprint(&self, ident: &Vec<u8>)
        -> Option<&Authority>
    {
        for fprint in self.contents.iter() {
            if fprint.keys.fingerprint.eq(ident) {
                return Some(fprint)
            }
        }

        None
    }

    pub fn import_authority(&mut self,
                            identity: Vec<u8>,
                            hostname: String, dirport: u16,
                            name: String, address: Ipv4Addr, orport: u16)
    {
        let mut core = new_core();
        let url = format!("http://{}:{}/tor/keys/authority.z",hostname,dirport);

        let uri = match url.parse() {
            Err(e) => {
                error!(target: "authority",
                       "Couldn't parse new authority URL {}: {}",
                       url, e);
                return;
            }
            Ok(v) => v
        };

        let get = fetch_and_parse!(&core.handle(), uri, 5,
                                   parse_authority_keys);

        match core.run(get) {
            Err(e) => {
                error!(target: "authority",
                       "Couldn't import new authority {:?}: {:?}",
                       name, e);
                return;
            }
            Ok(v) => {
                info!(target: "authority",
                      "Imported new authority {:?}",
                      name);
                let newauth = Authority {
                    nickname: name.clone(),
                    address: address.clone(),
                    ip6_address: None, // FIXME: Try to determine this?
                    onion_port: orport,
                    dir_port: dirport,
                    v3_ident: identity.clone(),
                    keys: v
                };
                self.contents.push(newauth);
            }
        }
    }
}

pub fn initial_authorities() -> Vec<Authority> {
    let mut core    = new_core();
    let mut futures = Vec::new();
    let     handle  = &core.handle();

    for default in DEFAULT_AUTHORITIES.iter() {
        // fetch the link for the authority key file
        let uri_str = format!("http://{:?}:{:?}/tor/keys/authority.z",
                              default.address, default.dir_port);
        let uri = match uri_str.parse() {
            Err(e) => {
                error!(target: "authority",
                       "Couldn't parse directory link {:?}: {:?}",
                       uri_str, e);
                continue
            }
            Ok(uri) => uri
        };
        // make the getter.
        let base_get = fetch_and_parse!(handle, uri, 5, parse_authority_keys);
        // make sure to save the nickname of this thing with the error, if
        // we get an error. also, we don't want everything to fail if one
        // part fails, so convert errors to an Err result.
        let get = base_get.then(move |keys| lift_keys(default, keys));
        futures.push(get);
    }

    let fetch = join_all(futures);
    // the type below is necessary, to force 'E' in the Futures
    let futures_res = core.run(fetch);
    let mut everything = futures_res.unwrap();

    let mut results: Vec<Authority> = Vec::new();
    for v in everything.drain(..) {
        match v {
            Ok(v) => {
                info!(target: "authority", "Imported default authority {:?}",
                      v.nickname);
                results.push(v);
            }
            Err((n, e)) => {
                warn!(target: "authority",
                      "Failed to import default authority {:?} ({})",
                      n, auth_error_str(e));
            }
        }
    }
    info!(target: "authority", "Integrated {} of {} default authorities.",
          results.len(), DEFAULT_AUTHORITIES.len());

    results
}

fn auth_error_str(afe: FetchErrors<AuthInfoErr>) -> String {
    match afe {
        FetchErrors::IOError(ref e)     => format!("IO Error: {:?}", e),
        FetchErrors::HTTPError(ref e)   => format!("HTTP Error: {:?}", e),
        FetchErrors::DecodeError(ref e) => format!("Decoding Error: {:?}", e),
        FetchErrors::BadURL             => "Couldn't parse URL".to_string(),
        FetchErrors::Timeout            => "Timeout waiting for authority info".to_string(),
        FetchErrors::ParseError(ref e)  => format!("Parse Error: {:?}", e)
    }
}

fn lift_keys(default: &DefaultAuthority,
             v: Result<AuthorityKeys,FetchErrors<AuthInfoErr>>)
    -> Result<Result<Authority,(String,FetchErrors<AuthInfoErr>)>,()>
{
    match v {
        Ok(v)  => Ok(Ok(Authority {
                       nickname: default.nickname.clone(),
                       address: default.address,
                       ip6_address: default.ip6_address,
                       onion_port: default.onion_port,
                       dir_port: default.dir_port,
                       v3_ident: default.v3_ident.clone(),
                       keys: v
        })),
        Err(e) => Ok(Err((default.nickname.clone(), e)))
    }
}


