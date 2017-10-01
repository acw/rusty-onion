use chrono::{DateTime,TimeZone,Utc};
use nom::ErrorKind;
use parsing_utils::{PortInfo,ProtocolVersion,TorAddress};
use std::collections::HashMap; use std::net::Ipv4Addr;
use std::ffi::OsString;

#[derive(Debug,Eq,PartialEq)]
pub struct Version {
    pub version_numbers: Vec<u8>,
    pub version_tag: String
}

#[derive(Debug)]
pub struct Consensus {
    pub network_status_version: u8,
    pub consensus_method: u8,
    pub valid_after: DateTime<Utc>,
    pub fresh_until: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub client_versions: Vec<Version>,
    pub server_versions: Vec<Version>,
    pub known_flags: Vec<Flag>,
    pub recommended_client_protocols: Vec<ProtocolVersion>,
    pub recommended_relay_protocols: Vec<ProtocolVersion>,
    pub required_client_protocols: Vec<ProtocolVersion>,
    pub required_relay_protocols: Vec<ProtocolVersion>,
    pub global_parameters: Vec<Parameter>,
    pub shared_rand_previous: Vec<u8>,
    pub shared_rand_current: Vec<u8>,
    pub bandwidth_weights: HashMap<String,i32>,
    pub directory_sources: Vec<DirectorySource>,
    pub routers: Vec<RouterInfo>,
}

#[derive(Debug)]
pub enum ConsensusParseErr {
    NotEnoughData,
    TooMuchData,
    ParserError(ErrorKind<u32>),
    TooFewStatus, TooManyStatus,
    TooManyValidAfters, TooManyFrushUntils, TooManyValidUntils,
    TooFewVoteDelays, TooManyVoteDelays,
    TooManyClientVersions, TooManyServerVersions,
    TooFewFlags, TooManyFlags,
    TooManyRecClientProtocols, TooManyRecRelayProtocols,
    TooManyReqClientProtocols, TooManyReqRelayProtocols,
    TooManyParameters,
    TooManySharedRandPrev, TooManySharedRandCur,
    TooFewRouterFlags, TooManyRouterFlags,
    TooManyRouterVersions,
    TooManyProtocolLines, TooManyBandwidthLines, TooManyPortLists,
    WeirdBrokenError(u32)
}

pub fn empty_consensus(v: u8) -> Consensus
{
    Consensus {
        network_status_version: v,
        consensus_method: 0,
        valid_after: Utc.ymd(1978,3,4).and_hms(7,0,0),
        fresh_until: Utc.ymd(1978,3,4).and_hms(7,0,0),
        valid_until: Utc.ymd(1978,3,4).and_hms(7,0,0),
        client_versions: Vec::new(),
        server_versions: Vec::new(),
        known_flags: Vec::new(),
        recommended_client_protocols: Vec::new(),
        recommended_relay_protocols: Vec::new(),
        required_client_protocols: Vec::new(),
        required_relay_protocols: Vec::new(),
        global_parameters: Vec::new(),
        shared_rand_previous: Vec::new(),
        shared_rand_current: Vec::new(),
        bandwidth_weights: HashMap::new(),
        directory_sources: Vec::new(),
        routers: Vec::new(),
    }
}
//
//
//pub enum ConsensusMethod { Vote, Consensus }
//
#[derive(Debug,Eq,PartialEq)]
pub enum Flag { Authority, BadExit, Exit, Fast, Guard, HSDir, NoEdConsensus,
                Running, Stable, V2Dir, Valid,
                // UnknownFlag(String) FIXME: Add this back when it works again
                }

#[derive(Debug,Eq,PartialEq)]
pub enum Parameter {
  DefaultCircuitPackageWindow(i32),
  CircuitHalfLife(i32),
  PerConnBWRate(i32),
  PerConnBWBurst(i32),
  RefuseUnknownExits(i32),
  BandwidthWeightScale(i32),
  CircBuildTimeDisabled(i32),
  CircBuildTimeNumModes(i32),
  CircBuildTimeRecentCount(i32),
  CircBuildTimeMaxTimeouts(i32),
  CircBuildTimeMinCircuits(i32),
  CircBuildTimeQuantile(i32),
  CircBuildTimeCloseQuantile(i32),
  CircBuildTimeTestFreq(i32),
  CircBuildTimeMinTimeout(i32),
  CircBuildTimeInitialTimeout(i32),
  UseOptimisticData(i32),
  MaxUnmeasuredBandwidth(i32),
  Support022HiddenServices(i32),
  UseCreateFast(i32),
  PBMinCircuits(i32),
  PBNoticePercent(i32),
  PBWarnPercent(i32),
  PBExtremePercent(i32),
  PBDropGuards(i32),
  PBScaleCircuits(i32),
  PBScaleFactor(i32),
  PBMultFactor(i32),
  PBMinUse(i32),
  PBNoticeUsePercent(i32),
  PBExtremeUsePercent(i32),
  PBScaleUse(i32),
  UseNTorHandshake(i32),
  FastFlagMinThreshold(i32),
  FastFlagMaxThreshold(i32),
  NumDirectoryGuards(i32),
  NumEntryGuards(i32),
  GuardLifetime(i32),
  MinPathsForCircuitsPercent(i32),
  NumNTorsPerTAP(i32),
  AllowNonearlyExtend(i32),
  AuthDirNumServerVoteAgreements(i32),
  MaxConsensusAgeForDiff(i32),
  TryDiffForNewerConsense(i32),
  OnionKeyRotationDays(i32),
  OnionKeyGracePeriodDays(i32),
  UnknownParameter(String,i32)
}

#[derive(Debug,Eq,PartialEq)]
pub struct DirectorySource {
    pub name: String,
    pub identity: Vec<u8>,
    pub hostname: String,
    pub address: Ipv4Addr,
    pub dirport: u16,
    pub orport: u16,
    pub contact_info: OsString,
    pub vote_digest: Vec<u8>
}

#[derive(Debug,Eq,PartialEq)]
pub struct RouterInfo {
    pub nickname: String,
    pub identity: Vec<u8>,
    pub digest: Vec<u8>,
    pub publication_time: DateTime<Utc>,
    pub main_address: Ipv4Addr,
    pub main_or_port: u16,
    pub dir_port: u16,
    pub other_addresses: Vec<(TorAddress,u16)>,
    pub flags: Vec<Flag>,
    pub version: Version,
    pub subprotocol_versions: Vec<ProtocolVersion>,
    pub bandwidth_info: Vec<BandwidthData>,
    pub exit_port_information: Vec<PortInfo>
}

#[derive(Debug)]
pub struct DirectorySignature {
    pub identity: Vec<u8>,
    pub algorithm: SignatureAlgorithm,
    pub signing_key_digest: Vec<u8>,
    pub signature: Vec<u8>
}

#[derive(Debug)]
pub enum SignatureAlgorithm { SigSHA1, SigSHA256 }

#[derive(Debug,Eq,PartialEq)]
pub enum BandwidthData {
    Estimate(u64),
    Measured(u64),
    Unmeasured,
    UnknownBandwidthData(String,i64)
}
