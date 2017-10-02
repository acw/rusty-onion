use chrono::{DateTime,Utc};
use nom::ErrorKind;
use parsing_utils::{PortInfo,ProtocolVersion,TorAddress};
use std::ffi::OsString;
use std::net::Ipv4Addr;

pub struct ServerDescriptor {
    pub nickname: String,
    pub address: Ipv4Addr,
    pub or_port: Option<u16>,
    pub dir_port: Option<u16>,
    pub ed25519_identity_cert: Option<Vec<u8>>,
    pub ed25519_master_key: Option<Vec<u8>>,
    pub bandwidth: BandwidthMeasurement,
    pub platform: Option<OsString>,
    pub published: DateTime<Utc>,
    pub fingerprint: Option<Vec<u8>>,
    pub hibernating: Option<bool>,
    pub uptime: u64,
    pub onion_key: Vec<u8>,
    pub ed25519_onion_key: Option<Vec<u8>>,
    pub signing_key: Vec<u8>,
    pub exit_policy: Vec<ExitPolicyRule>,
    pub exit_policy_ip6: Vec<PortInfo>,
    pub contact: OsString,
    pub family_names: Vec<FamilyDescriptor>,
    pub read_history: Option<HistoryInformation>,
    pub write_history: Option<HistoryInformation>,
    pub caches_extra_info: bool,
    pub extra_info_digest: Option<(Vec<u8>,Option<Vec<u8>>)>,
    pub stores_hidden_service_descriptors: Option<Vec<u8>>,
    pub allows_single_hop_exits: bool,
    pub other_addresses: Vec<(TorAddress, u16)>,
    pub accepts_tunneled_dir_requests: bool,
    pub protocol_versions: Vec<ProtocolVersion>
}

pub enum FamilyDescriptor {
    FamilyName(String),
    FamilyIdDigest(Vec<u8>),
    FamilyIdAndName(Vec<u8>,String)
}

pub struct BandwidthMeasurement {
    pub average: u64,
    pub burst: u64,
    pub observed: u64
}

pub struct ExitPolicyRule {
    pub address: Ipv4Addr,
    pub mask: u8,
    pub port_start: u16,
    pub port_end: u16,
    pub rule: AcceptReject
}

pub enum AcceptReject { Accept, Reject }

pub struct HistoryInformation {
    pub interval_nsecs: u64,
    pub interval_end: DateTime<Utc>,
    pub bandwidth_used: Vec<u64>
}

#[derive(Debug)]
pub enum ServerDescParseErr {
    NotEnoughData, TooManyFieldInstances, MissingField,
    OnionCrossCertCheckFailed,
    SignatureCheckFailed,
    ParserError(ErrorKind<u32>)
}
