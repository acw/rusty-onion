extern crate chrono;
extern crate nom;
extern crate parsing_utils;
extern crate ring;

pub mod types;
pub mod parser;

// use authority::AuthorityDatabase;
// use config::CONFIG;
// use flate2::write::ZlibDecoder;
// use futures::{Future,Stream};
// use futures::future::Either;
// use hyper::Client;
// use ring::signature::*;
// use routerdb::consensus::parser::parse_consensus;
// use routerdb::consensus::types::{Consensus,SignatureAlgorithm};
// use std::io::Write;
// use std::time::Duration;
// use tokio_core::reactor::Timeout;
// use untrusted::Input;
// use util::fetch::{FetchErrors,new_core};

// pub fn fetch_consensus(authdb: &mut AuthorityDatabase) -> Consensus {
//     let mut core   = new_core();
//     let     handle = &core.handle();
// 
//     // keep trying until we get one
//     loop {
//         let (uri, nickname) = {
//             let auth = authdb.random_authority();
//             let url =format!("http://{:?}:{:?}/tor/status-vote/current/consensus.z",
//                              auth.address, auth.dir_port);;
//             info!(target: "consensus", "Fetching consensus data from {:?} at {:?}",
//                   auth.nickname, url);
//             match url.parse() {
//                 Err(e) => {
//                     error!(target: "consensus",
//                            "Couldn't parse consensus URL ({}): {}", url, e);
//                     continue
//                 }
//                 Ok(v) => (v, auth.nickname.clone())
//             }
//         };
//         let get_consensus = fetch_and_parse!(handle, uri, 20, parse_consensus);
// 
//         match core.run(get_consensus) {
//             Ok((con, sigs, text)) => {
//                 let mut confirmed = 0;
//                 let mut unknown   = 0;
// 
//                 for sig in sigs.iter() {
//                     let mauth = authdb.authority_from_fingerprint(&sig.identity);
//                     match mauth {
//                         None => unknown = unknown + 1,
//                         Some(auth) => {
//                             let signing_key = Input::from(&auth.keys.signing_key);
//                             let signature = Input::from(&sig.signature);
//                             let body = Input::from(&text);
//                             let hash = match sig.algorithm {
//                                 SignatureAlgorithm::SigSHA1   =>
//                                     &RSA_PKCS1_NOSIG_2048_8192_SHA1,
//                                 SignatureAlgorithm::SigSHA256 =>
//                                     &RSA_PKCS1_NOSIG_2048_8192_SHA256
//                             };
//                             let res = verify(hash, signing_key, body, signature);
// 
//                             if res.is_err() {
//                                 warn!(target: "consensus",
//                                       "Consensus signature failed ({:?})",
//                                       auth.nickname);
//                                 continue
//                             }
// 
//                             confirmed += 1
//                         }
//                     }
//                 }
// 
//                 info!(target: "consensus",
//                       "Accepted consensus with {:?} verified and {:?} unknown signatures.",
//                       confirmed, unknown);
// 
//                 if confirmed < CONFIG.security.minimum_consensus_signatures {
//                     warn!(target: "consensus",
//                           "Verified {:?} consensus signatures, need {:?}",
//                           confirmed, CONFIG.security.minimum_consensus_signatures);
//                     continue
//                 }
// 
//                 if CONFIG.security.import_authorities_from_consensus {
//                     for sig in sigs.iter() {
//                         let do_import = {
//                             let v = authdb.authority_from_fingerprint(&sig.identity);
//                             v.is_none()
//                         };
//                         if do_import {
//                             authdb.import_authority(&con, &sig.identity);
//                         }
//                     }
//                 }
// 
//                 return con
//             }
//             Err(e)  =>
//                 warn!(target: "consensus",
//                       "Couldn't get consensus from {:?}: {:?}",
//                       nickname, e)
//         }
//     }
// }
