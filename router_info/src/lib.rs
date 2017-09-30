extern crate authority;
extern crate consensus;
extern crate tor_config;

use authority::AuthorityDatabase;
use consensus::{Consensus, fetch_consensus};
use tor_config::Config;

pub struct RouterDatabase {
    config: Config,
    consensus: Consensus
}

impl RouterDatabase {
    pub fn new(config: &Config, authdb: &mut AuthorityDatabase) -> RouterDatabase {
        let con = fetch_consensus(config, authdb);
        RouterDatabase {
            config: config.clone()
        ,   consensus: con
        }
    }

    pub fn count(&self) -> usize {
        self.consensus.routers.len()
    }
}
