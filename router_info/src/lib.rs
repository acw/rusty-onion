extern crate authority;
extern crate consensus;
#[macro_use]
extern crate log;
extern crate ring;
extern crate simple_rsa;
extern crate tor_config;

use authority::AuthorityDatabase;
use consensus::{Consensus, SignatureAlgorithm, fetch_consensus};
use ring::digest::{SHA1, SHA256, digest};
use simple_rsa::pkcs1_verify;
use tor_config::Config;

pub struct RouterDatabase {
    config: Config,
    authorities: AuthorityDatabase,
    consensus: Consensus
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

            return RouterDatabase {
                config: config.clone(),
                authorities: authdb,
                consensus: con
            }
        }
    }

    pub fn count(&self) -> usize {
        self.consensus.routers.len()
    }
}
