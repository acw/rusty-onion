extern crate authority;
extern crate base64;
extern crate chrono;
extern crate consensus;
#[macro_use]
extern crate fetch;
extern crate flate2;
extern crate futures;
extern crate hyper;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
extern crate parsing_utils;
extern crate ring;
extern crate tokio_core;
extern crate tor_config;
extern crate tor_crypto;
extern crate untrusted;

mod types;
mod parser;

use authority::AuthorityDatabase;
use consensus::{Consensus, SignatureAlgorithm, fetch_consensus};
use fetch::{FetchErrors,new_core};
use flate2::write::ZlibDecoder;
use futures::{Future,Stream};
use futures::future::Either;
use hyper::Client;
use parser::parse_server_descriptors;
use ring::digest::{SHA1, SHA256, digest};
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio_core::reactor::Timeout;
use tor_config::Config;
use tor_crypto::pkcs1_verify;
use types::{ServerDescriptor,ServerDescParseErr};

pub struct RouterDatabase {
    authorities: AuthorityDatabase,
    consensus: Consensus,
    routers: Vec<ServerDescriptor>
}

impl RouterDatabase {
    pub fn new(config: &Config) -> RouterDatabase {
        let mut authdb = AuthorityDatabase::new();

        // Keep trying this forever, until we get what we want.
        loop {
            let (con, sigs, body, nickname) = {
                let authdb = &mut authdb;
                let auth = authdb.random_authority();
                match fetch_consensus(auth.address, auth.dir_port) {
                    Ok((a,b,c))  => (a,b,c,auth.nickname.clone()),
                    Err(e) => {
                        warn!(target: "consensus",
                              "Error getting consens from {} ({:?})",
                              auth.nickname, e);
                        continue
                    }
                }
            };
            let hash_sha1 = digest(&SHA1, &body);
            let hash_sha256 = digest(&SHA256, &body);

            let mut confirmed = 0;
            let mut unknown = Vec::new();

            for sig in sigs.iter() {
                let mauth = &authdb.authority_from_fingerprint(&sig.identity);
                let auth = match mauth {
                             &Some(ref v) => v,
                             &None    => {
                                 unknown.push(sig);
                                 continue;
                             }
                };
                let hash = match sig.algorithm {
                             SignatureAlgorithm::SigSHA1 => hash_sha1,
                             SignatureAlgorithm::SigSHA256 => hash_sha256
                };

                if pkcs1_verify(&auth.keys.signing_key, &[], hash.as_ref(), &sig.signature) {
                    confirmed += 1;
                } else {
                    warn!(target: "consensus", "Consensus signature failed ({})", nickname);
                }
            }

            if confirmed < config.security.minimum_consensus_signatures {
                warn!(target: "consensus",
                      "Verified {} consensus signatures, need {}",
                      confirmed, config.security.minimum_consensus_signatures);
                continue;
            } else {
                info!(target: "consensus",
                      "Accepting consensus based on {} confirmed authorities.",
                      confirmed);
            }

            info!(target: "authority",
                  "Consensus includes {} authorities ({} unknown)",
                  con.directory_sources.len(), unknown.len());
            if config.security.import_authorities_from_consensus {
                for sig in unknown.iter() {
                    for src in &con.directory_sources {
                        if src.identity.eq(&sig.identity) {
                            let authdb = &mut authdb;
                            authdb.import_authority(src.identity.clone(),
                                                    src.hostname.clone(),
                                                    src.dirport,
                                                    src.name.clone(),
                                                    src.address,
                                                    src.orport);
                        }
                    }
                }
            }

            // we don't really want to go back and redo all the consensus work
            // if this fails, so we do this as a subloop.
            loop {
                let rdb = {
                    let auth = authdb.random_authority();
                    match fetch_routerdb(auth.address, auth.dir_port) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(target: "routerdb",
                                  "Error fetching router db from {}: {:?}",
                                  auth.nickname, e);
                            continue
                        }
                    }
                };
                info!(target: "routerdb",
                      "Captured server descriptors for {} servers.",
                      rdb.len());

                return RouterDatabase {
                    authorities: authdb,
                    consensus: con,
                    routers: rdb
                }
            }
        }
    }

    pub fn count(&self) -> usize {
        self.consensus.routers.len()
    }
}

fn fetch_routerdb(addr: Ipv4Addr, port: u16)
    -> Result<Vec<ServerDescriptor>,FetchErrors<ServerDescParseErr>>
{
    let mut core = new_core();
    let handle = &core.handle();

    let uri = {
        let url = format!("http://{}:{}/tor/server/all.z", addr, port);
        match url.parse() {
            Err(e) => {
                error!(target: "routerdb",
                       "Couldn't parse router db URL ({}): {}", url, e);
                return Err(FetchErrors::BadURL);
            }
            Ok(v) => {
                info!(target: "routerdb", "Fetching router data from {}", url);
                v
            }
        }
    };

    let get_routerdb = fetch_and_parse!(handle, uri, 20, parse_server_descriptors);
    core.run(get_routerdb)
}
