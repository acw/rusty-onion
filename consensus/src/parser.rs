use chrono::{DateTime,Utc};
use nom::*;
use nom::ErrorKind;
use std::collections::HashMap;
use std::ffi::OsString;
use std::iter::FromIterator;
use std::str;
use types::*;
use types::BandwidthData::*;
use types::Flag::*;
use types::Parameter::*;
use types::SignatureAlgorithm::*;
use parsing_utils::*;

pub fn parse_consensus(i: &[u8])
    -> Result<(Consensus,Vec<DirectorySignature>,Vec<u8>),ConsensusParseErr>
{
    match parse_raw_consensus(i) {
        IResult::Error(e)      => Err(translate_error(e)),
        IResult::Incomplete(_) => Err(ConsensusParseErr::NotEnoughData),
        IResult::Done(b"", (c, sigs, body)) => Ok((c, sigs, body.to_vec())),
        IResult::Done(_, _)    => Err(ConsensusParseErr::TooMuchData)
    }
}

fn translate_error(e: ErrorKind<u32>) -> ConsensusParseErr {
    match e {
        ErrorKind::Custom(v) =>
            match v  {
                100 => ConsensusParseErr::TooFewStatus,
                101 => ConsensusParseErr::TooManyStatus,
                102 => ConsensusParseErr::TooManyValidAfters,
                103 => ConsensusParseErr::TooManyFrushUntils,
                104 => ConsensusParseErr::TooManyValidUntils,
                105 => ConsensusParseErr::TooFewVoteDelays,
                106 => ConsensusParseErr::TooManyVoteDelays,
                107 => ConsensusParseErr::TooManyClientVersions,
                108 => ConsensusParseErr::TooManyServerVersions,
                109 => ConsensusParseErr::TooFewFlags,
                110 => ConsensusParseErr::TooManyFlags,
                111 => ConsensusParseErr::TooManyRecClientProtocols,
                112 => ConsensusParseErr::TooManyRecRelayProtocols,
                113 => ConsensusParseErr::TooManyReqClientProtocols,
                114 => ConsensusParseErr::TooManyReqRelayProtocols,
                115 => ConsensusParseErr::TooManyParameters,
                116 => ConsensusParseErr::TooManySharedRandPrev,
                117 => ConsensusParseErr::TooManySharedRandCur,
                300 => ConsensusParseErr::TooFewRouterFlags,
                301 => ConsensusParseErr::TooManyRouterFlags,
                302 => ConsensusParseErr::TooManyRouterVersions,
                303 => ConsensusParseErr::TooManyProtocolLines,
                304 => ConsensusParseErr::TooManyBandwidthLines,
                305 => ConsensusParseErr::TooManyPortLists,
                _   => ConsensusParseErr::WeirdBrokenError(v)
            },
        _           => ConsensusParseErr::ParserError(e)
    }
}

fn parse_raw_consensus(i: &[u8])
    -> IResult<&[u8],(Consensus,Vec<DirectorySignature>,&[u8])>
{
    match parse_consensus_nosigs(i) {
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(i) => IResult::Incomplete(i),
        IResult::Done(rest,res) => {
            let startlen = i.len() - rest.len();
            // "directory-signature " takes 20 characters
            let hashlen = startlen + 20;

            match directory_signatures(rest) {
                IResult::Error(e) => IResult::Error(e),
                IResult::Incomplete(i) => IResult::Incomplete(i),
                IResult::Done(extra,sigs) => {
                    IResult::Done(extra, (res, sigs, &i[0..hashlen]))
                }
            }
        }
    }
}

named!(parse_consensus_nosigs<Consensus>,
    do_parse!(
        initial: section1             >>
        sources: section2             >>
        routers: section3             >>
                 directory_footer     >>
        weights: bandwidth_weights    >>
        ( Consensus {
             network_status_version: initial.network_status_version,
             consensus_method: initial.consensus_method,
             valid_after: initial.valid_after,
             fresh_until: initial.fresh_until,
             valid_until: initial.valid_until,
             client_versions: initial.client_versions,
             server_versions: initial.server_versions,
             known_flags: initial.known_flags,
             recommended_client_protocols: initial.recommended_client_protocols,
             recommended_relay_protocols: initial.recommended_relay_protocols,
             required_client_protocols: initial.required_client_protocols,
             required_relay_protocols: initial.required_relay_protocols,
             global_parameters: initial.global_parameters,
             shared_rand_previous: initial.shared_rand_previous,
             shared_rand_current: initial.shared_rand_current,
             bandwidth_weights: weights,
             directory_sources: sources,
             routers: routers,
        })
    )
);

//------------------------------------------------------------------------------
//
// In the first section of the consensus file, the Tor directory specification
// declares which fields can be used and how many times they may be used, but
// does not specify an order. The following structures and functions do the
// book-keeping we're going to need in parsing these, to ensure that we hit the
// "exactly once" and "at least once" requirements correctly without dictating
// order.
//
//------------------------------------------------------------------------------

#[derive(Debug)]
struct Section1Counts {
    vote_status: u64,
    consensus_method: u64,
    valid_after: u64,
    fresh_until: u64,
    valid_until: u64,
    voting_delay: u64,
    client_versions: u64,
    server_versions: u64,
    known_flags: u64,
    rec_client_protos: u64,
    rec_relay_protos: u64,
    req_client_protos: u64,
    req_relay_protos: u64,
    params: u64,
    shared_rand_prev: u64,
    shared_rand_cur: u64
}

const BASE_SECTION1_COUNTS: Section1Counts = Section1Counts {
    vote_status: 0,
    consensus_method: 0,
    valid_after: 0,
    fresh_until: 0,
    valid_until: 0,
    voting_delay: 0,
    client_versions: 0,
    server_versions: 0,
    known_flags: 0,
    rec_client_protos: 0,
    rec_relay_protos: 0,
    req_client_protos: 0,
    req_relay_protos: 0,
    params: 0,
    shared_rand_prev: 0,
    shared_rand_cur: 0
};

// Error codes for this part of the parser
const TOO_FEW_STATUS            : u32 = 100;
const TOO_MANY_STATUS           : u32 = 101;
const TOO_MANY_VALID_AFTER      : u32 = 102;
const TOO_MANY_FRESH_UNTIL      : u32 = 103;
const TOO_MANY_VALID_UNTIL      : u32 = 104;
const TOO_FEW_VDELAY            : u32 = 105;
const TOO_MANY_VDELAY           : u32 = 106;
const TOO_MANY_CLIENT_VER       : u32 = 107;
const TOO_MANY_SERVER_VER       : u32 = 108;
const TOO_FEW_FLAGS             : u32 = 109;
const TOO_MANY_FLAGS            : u32 = 110;
const TOO_MANY_RECCP            : u32 = 111;
const TOO_MANY_RECRP            : u32 = 112;
const TOO_MANY_REQCP            : u32 = 113;
const TOO_MANY_REQRP            : u32 = 114;
const TOO_MANY_PARAMS           : u32 = 115;
const TOO_MANY_SHARED_RAND_PREV : u32 = 116;
const TOO_MANY_SHARED_RAND_CUR  : u32 = 117;

fn sec1_counts_meet_requirements(counts: Section1Counts) -> Result<(),u32> {
    try!(exactly_once(counts.vote_status, TOO_FEW_STATUS, TOO_MANY_STATUS));
    try!(at_most_once(counts.valid_after, TOO_MANY_VALID_AFTER));
    try!(at_most_once(counts.fresh_until, TOO_MANY_FRESH_UNTIL));
    try!(at_most_once(counts.valid_until, TOO_MANY_VALID_UNTIL));
    try!(exactly_once(counts.voting_delay, TOO_FEW_VDELAY, TOO_MANY_VDELAY));
    try!(at_most_once(counts.client_versions, TOO_MANY_CLIENT_VER));
    try!(at_most_once(counts.server_versions, TOO_MANY_SERVER_VER));
    try!(exactly_once(counts.known_flags, TOO_FEW_FLAGS, TOO_MANY_FLAGS));
    try!(at_most_once(counts.rec_client_protos, TOO_MANY_RECCP));
    try!(at_most_once(counts.rec_relay_protos, TOO_MANY_RECRP));
    try!(at_most_once(counts.req_client_protos, TOO_MANY_REQCP));
    try!(at_most_once(counts.req_relay_protos, TOO_MANY_REQRP));
    try!(at_most_once(counts.params, TOO_MANY_PARAMS));
    try!(at_most_once(counts.shared_rand_prev, TOO_MANY_SHARED_RAND_PREV));
    try!(at_most_once(counts.shared_rand_cur, TOO_MANY_SHARED_RAND_CUR));
    Result::Ok(())
}

fn section1(i: &[u8]) -> IResult<&[u8], Consensus>
{
    match status_version(&i) {
        IResult::Done(iprime,version) => {
            let mut cur = empty_consensus(version);
            let mut counts = BASE_SECTION1_COUNTS;
            let mut buffer = iprime;

            loop {
                match section1_bit(&mut cur, &mut counts, buffer) {
                    Some(newbuffer) => buffer = newbuffer,
                    None            => break
                }
            }

            match sec1_counts_meet_requirements(counts) {
                Result::Err(v) =>
                    IResult::Error(error_code!(ErrorKind::Custom(v))),
                Result::Ok(_) =>
                    IResult::Done(buffer, cur)
            }

        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(v) => IResult::Incomplete(v)
    }
}

fn section1_bit<'a>(doc: &mut Consensus,
                    counts: &mut Section1Counts,
                    i: &'a[u8]) -> Option<&'a[u8]>
{
    try_parser_!(i, vote_status, counts.vote_status);
    try_parser!(i, consensus_method, counts.consensus_method,
                    doc.consensus_method);
    try_parser!(i, valid_after, counts.valid_after, doc.valid_after);
    try_parser!(i, fresh_until, counts.fresh_until, doc.fresh_until);
    try_parser!(i, valid_until, counts.valid_until, doc.valid_until);
    try_parser_!(i, voting_delay, counts.voting_delay);
    try_parser!(i, client_versions, counts.client_versions,
                    doc.client_versions);
    try_parser!(i, server_versions, counts.server_versions,
                    doc.server_versions);
    try_parser!(i, known_flags, counts.known_flags, doc.known_flags);
    try_parser!(i, rec_client_prot, counts.rec_client_protos,
                    doc.recommended_client_protocols);
    try_parser!(i, req_client_prot, counts.req_client_protos,
                    doc.required_client_protocols);
    try_parser!(i, rec_relay_prot, counts.rec_relay_protos,
                    doc.recommended_relay_protocols);
    try_parser!(i, req_relay_prot, counts.req_relay_protos,
                    doc.required_relay_protocols);
    try_parser!(i, params, counts.params, doc.global_parameters);
    try_parser!(i, shared_rand_prev, counts.shared_rand_prev,
                    doc.shared_rand_previous);
    try_parser!(i, shared_rand_cur, counts.shared_rand_cur,
                    doc.shared_rand_current);

    None
}

named!(status_version<u8>,
    do_parse!(
        tag!("network-status-version") >>
        space                          >>
        d: decimal_u8                  >>
        newline                        >>
        (d)
    )
);

named!(vote_status<()>,
    do_parse!(
        tag!("vote-status")       >>
        space                     >>
        tag!("consensus")         >>
        newline                   >>
        (())
    )
);

named!(consensus_method<u8>,
    do_parse!(
        tag!("consensus-method") >>
        space                    >>
        d: decimal_u8            >>
        newline                  >>
        (d)
    )
);

named!(valid_after<DateTime<Utc>>,
    do_parse!(
        tag!("valid-after") >>
        sp >>
        d: datetime >>
        newline >>
        (d)
    )
);

named!(fresh_until<DateTime<Utc>>,
    do_parse!(
        tag!("fresh-until") >>
        sp >>
        d: datetime >>
        newline >>
        (d)
    )
);

named!(valid_until<DateTime<Utc>>,
    do_parse!(
        tag!("valid-until") >>
        sp >>
        d: datetime >>
        newline >>
        (d)
    )
);

named!(voting_delay<()>,
    do_parse!(
        tag!("voting-delay") >>
        space                >>
        decimal_u64          >>
        space                >>
        decimal_u64          >>
        newline              >>
        (())
    )
);

named!(client_versions<Vec<Version>>,
    do_parse!(
        tag!("client-versions")                         >>
        space                                           >>
        vs: separated_nonempty_list!(tag!(","),version) >>
        newline                                         >>
        (vs)
    )
);

named!(server_versions<Vec<Version>>,
    do_parse!(
        tag!("server-versions")                         >>
        space                                           >>
        vs: separated_nonempty_list!(tag!(","),version) >>
        newline                                         >>
        (vs)
    )
);

named!(known_flags<Vec<Flag>>,
    do_parse!(
        tag!("known-flags")                                             >>
        space                                                           >>
        fs: separated_nonempty_list_complete!(sp,known_flag) >>
        newline                                                         >>
        (fs)
    )
);

named!(known_flag<Flag>,
    alt!(
        do_parse!(tag!("Authority")     >> (Authority))     |
        do_parse!(tag!("BadExit")       >> (BadExit))       |
        do_parse!(tag!("Exit")          >> (Exit))          |
        do_parse!(tag!("Fast")          >> (Fast))          |
        do_parse!(tag!("Guard")         >> (Guard))         |
        do_parse!(tag!("HSDir")         >> (HSDir))         |
        do_parse!(tag!("NoEdConsensus") >> (NoEdConsensus)) |
        do_parse!(tag!("Running")       >> (Running))       |
        do_parse!(tag!("Stable")        >> (Stable))        |
        do_parse!(tag!("V2Dir")         >> (V2Dir))         |
        do_parse!(tag!("Valid")         >> (Valid))
//  FIXME: This parser should be a bit more tolerant, and return Unknown.
//  However, I'm running into puzzling parser problems and, well, I'm tired
//  of diagnosing the problem.
//        |
//        do_parse!(v: alphanumeric       >>
//                  (UnknownFlag(str::from_utf8(v).unwrap().to_string())))
    )
);

named!(rec_client_prot<Vec<ProtocolVersion>>,
    do_parse!(
        tag!("recommended-client-protocols")                        >>
        space                                                       >>
        res: separated_nonempty_list_complete!(sp,protocol_version) >>
        newline                                                     >>
        (res)
    )
);

named!(req_client_prot<Vec<ProtocolVersion>>,
    do_parse!(
        tag!("required-client-protocols")                           >>
        space                                                       >>
        res: separated_nonempty_list_complete!(sp,protocol_version) >>
        newline                                                     >>
        (res)
    )
);

named!(rec_relay_prot<Vec<ProtocolVersion>>,
    do_parse!(
        tag!("recommended-relay-protocols")                         >>
        space                                                       >>
        res: separated_nonempty_list_complete!(sp,protocol_version) >>
        newline                                                     >>
        (res)
    )
);

named!(req_relay_prot<Vec<ProtocolVersion>>,
    do_parse!(
        tag!("required-relay-protocols")                            >>
        space                                                       >>
        res: separated_nonempty_list_complete!(sp,protocol_version) >>
        newline                                                     >>
        (res)
    )
);

named!(params<Vec<Parameter>>,
    do_parse!(
        tag!("params")                                     >>
        space                                              >>
        x: separated_nonempty_list_complete!(sp,parameter) >>
        newline                                            >>
        (x)
    )
);

named!(parameter<Parameter>,
    do_parse!(
        kw: keyword >>
        tag!("=") >>
        val: decimal_i32 >>
        (build_parameter(kw, val))
    )
);

named!(shared_rand_prev<Vec<u8>>,
    do_parse!(
        tag!("shared-rand-previous-value") >>
        space                              >>
        decimal_u8                         >>
        space                              >>
        v: base64val                       >>
        newline                            >>
        (v)
    )
);

named!(shared_rand_cur<Vec<u8>>,
    do_parse!(
        tag!("shared-rand-current-value") >>
        space                             >>
        decimal_u8                        >>
        space                             >>
        v: base64val                      >>
        newline                           >>
        (v)
    )
);

fn build_parameter(name: &str, value: i32) -> Parameter
{
    match name {
        "circwindow" => DefaultCircuitPackageWindow(value),
        "CircuitPriorityHalflifeMsec" => CircuitHalfLife(value),
        "perconnbwrate" => PerConnBWRate(value),
        "perconnbwburst" => PerConnBWBurst(value),
        "refuseunknownexits" => RefuseUnknownExits(value),
        "bwweightscale" => BandwidthWeightScale(value),
        "cbtdisabled" => CircBuildTimeDisabled(value),
        "cbtnummodes" => CircBuildTimeNumModes(value),
        "cbtrecentcount" => CircBuildTimeRecentCount(value),
        "cbtmaxtimeouts" => CircBuildTimeMaxTimeouts(value),
        "cbtmincircs" => CircBuildTimeMinCircuits(value),
        "cbtquantile" => CircBuildTimeQuantile(value),
        "cbtclosequantile" => CircBuildTimeCloseQuantile(value),
        "cbttestfreq" => CircBuildTimeTestFreq(value),
        "cbtmintimeout" => CircBuildTimeMinTimeout(value),
        "cbtinitialtimeout" => CircBuildTimeInitialTimeout(value),
        "UseOptimisticData" => UseOptimisticData(value),
        "maxunmeasuredbw" => MaxUnmeasuredBandwidth(value),
        "Support022HiddenServices" => Support022HiddenServices(value),
        "usecreatefast" => UseCreateFast(value),
        "pb_mincircs" => PBMinCircuits(value),
        "pb_noticepct" => PBNoticePercent(value),
        "pb_warnpct" => PBWarnPercent(value),
        "pb_extremepct" => PBExtremePercent(value),
        "pb_dropguards" => PBDropGuards(value),
        "pb_scalecircs" => PBScaleCircuits(value),
        "pb_scalefactor" => PBScaleFactor(value),
        "pb_multfactor" => PBMultFactor(value),
        "pb_minuse" => PBMinUse(value),
        "pb_noticeusepct" => PBNoticeUsePercent(value),
        "pb_extremeusepct" => PBExtremeUsePercent(value),
        "pb_scaleuse" => PBScaleUse(value),
        "UseNTorHandshake" => UseNTorHandshake(value),
        "FastFlagMinThreshold" => FastFlagMinThreshold(value),
        "FastFlagMaxThreshold" => FastFlagMaxThreshold(value),
        "NumDirectoryGuards" => NumDirectoryGuards(value),
        "NumEntryGuards" => NumEntryGuards(value),
        "GuardLifetime" => GuardLifetime(value),
        "min_paths_for_circs_pct" => MinPathsForCircuitsPercent(value),
        "NumNTorsPerTAP" => NumNTorsPerTAP(value),
        "AllowNonearlyExtend" => AllowNonearlyExtend(value),
        "AuthDirNumSRVAgreements" => AuthDirNumServerVoteAgreements(value),
        "max-consensuses-age-to-cache-for-diff" =>MaxConsensusAgeForDiff(value),
        "try-diff-for-consensus-newer-than" => TryDiffForNewerConsense(value),
        "onion-key-rotation-days" => OnionKeyRotationDays(value),
        "onion-key-grace-period-days" => OnionKeyGracePeriodDays(value),
        _ => UnknownParameter(name.to_string(), value)
    }
}

const KEYWORD_CHARS: &'static str =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

named!(keyword<&str>,map_res!(is_a!(KEYWORD_CHARS.as_bytes()),
                              |v| str::from_utf8(v)));

named!(version<Version>,
    do_parse!(
       base: separated_nonempty_list_complete!(tag!("."),decimal_u8) >>
       tag: opt!(complete!(do_parse!(
                   tag!("-")                                   >>
                   v: is_not!(NEWLINE_CHAR)                    >>
                   (str::from_utf8(v).unwrap().to_string())))) >>
       (match tag {
           None    => Version{version_numbers:base, version_tag:"".to_string()},
           Some(t) => Version{version_numbers:base, version_tag:t  }
        })
    )
);

//------------------------------------------------------------------------------
//
// In the second section of the consensus file, we get a bunch of directory
// sources, and their relevant information.
//
//------------------------------------------------------------------------------

named!(section2<Vec<DirectorySource>>,
    do_parse!(
        r: separated_nonempty_list_complete!(newline,
             complete!(directory_source)) >>
        newline >>
        (r)
    )
);

named!(directory_source<DirectorySource>,
    do_parse!(
        tag!("dir-source") >> sp >> name: nickname >> sp >> ident: hexbytes >>
                              sp >> addr: hostname >> sp >> ip: ip4addr >>
                              sp >> dirport: decimal_u16 >> sp >>
                              orport: decimal_u16 >> newline >>
        tag!("contact") >> sp >> contact: generic_string >> newline >>
        tag!("vote-digest") >> sp >> digest: hexbytes >>
        (DirectorySource {
            name: name,
            identity: ident,
            hostname: addr,
            address: ip,
            dirport: dirport,
            orport: orport,
            contact_info: contact,
            vote_digest: digest
        })
    )
);

const WHITESPACE_CHARS: &'static str =
    " \t\n\r";

named!(hostname<String>,
    map_opt!(is_not!(WHITESPACE_CHARS), force_string));

//------------------------------------------------------------------------------
//
// Section 3! The list of routers in the consensus. Fairly straightforward,
// except that again the order of fields in not specified in the specification,
// so we need to keep counts to make sure that we get everything we need.
//
//------------------------------------------------------------------------------

struct Section3Counts {
    status_flags: u64,
    versions: u64,
    protocols: u64,
    bandwidths: u64,
    ports: u64,
}

const BASE_SECTION3_COUNTS: Section3Counts = Section3Counts {
    status_flags: 0,
    versions: 0,
    protocols: 0,
    bandwidths: 0,
    ports: 0,
};

// Error codes for this part of the parser
const TOO_FEW_ROUTER_FLAGS     : u32 = 300;
const TOO_MANY_ROUTER_FLAGS    : u32 = 301;
const TOO_MANY_ROUTER_VERSIONS : u32 = 302;
const TOO_MANY_PROTOCOL_LINES  : u32 = 303;
const TOO_MANY_BANDWIDTH_LINES : u32 = 304;
const TOO_MANY_PORT_LISTS      : u32 = 305;

fn sec3_counts_meet_requirements(counts: Section3Counts) -> Result<(),u32> {
    try!(exactly_once(counts.status_flags, TOO_FEW_ROUTER_FLAGS,
                      TOO_MANY_ROUTER_FLAGS));
    try!(at_most_once(counts.versions, TOO_MANY_ROUTER_VERSIONS));
    try!(at_most_once(counts.protocols, TOO_MANY_PROTOCOL_LINES));
    try!(at_most_once(counts.bandwidths, TOO_MANY_BANDWIDTH_LINES));
    try!(at_most_once(counts.ports, TOO_MANY_PORT_LISTS));
    Result::Ok(())
}

named!(section3<Vec<RouterInfo>>, many1!(complete!(section3_entry)));

fn section3_entry(i: &[u8]) -> IResult<&[u8], RouterInfo> {
    match router_header(&i) {
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(v) => IResult::Incomplete(v),
        IResult::Done(iprime,initial) => {
            let mut cur    = initial;
            let mut counts = BASE_SECTION3_COUNTS;
            let mut buffer = iprime;

            loop {
                match section3_bit(&mut cur, &mut counts, buffer) {
                    Some(newbuffer) => buffer = newbuffer,
                    None            => break
                }
            }

            match sec3_counts_meet_requirements(counts) {
                Result::Err(v) =>
                    IResult::Error(error_code!(ErrorKind::Custom(v))),
                Result::Ok(_) =>
                    IResult::Done(buffer, cur)
            }
        }
    }
}

fn section3_bit<'a>(r: &mut RouterInfo, c: &mut Section3Counts, i: &'a[u8])
    -> Option<&'a[u8]>
{
    // this first one doesn't quite fit our mold...
    match router_addr(i) {
        IResult::Done(newi, v) => {
            r.other_addresses.push(v);
            return Some(newi)
        }
        _ => ()
    }
    // but the rest work fine...
    try_parser!(i, router_status_flags, c.status_flags, r.flags);
    try_parser!(i, router_version, c.versions, r.version);
    try_parser!(i, router_protocols, c.protocols, r.subprotocol_versions);
    try_parser!(i, router_exitinfo, c.ports, r.exit_port_information);
    try_parser!(i, router_bandwidth, c.bandwidths, r.bandwidth_info);

    None
}

named!(router_header<RouterInfo>,
    do_parse!(
        tag!("r") >> sp >>
        n: nickname >> sp >>
        i: base64_noequals >> sp >>
        d: base64val >> sp >>
        p: datetime >> sp >>
        ip: ip4addr >> sp >>
        or: decimal_u16 >> sp >>
        dir: decimal_u16 >>
        newline >>
        (RouterInfo {
            nickname: n,
            identity: i,
            digest: d,
            publication_time: p,
            main_address: ip,
            main_or_port: or,
            dir_port: dir,
            other_addresses: Vec::new(),
            flags: Vec::new(),
            version: Version{ version_numbers: Vec::new(),
                              version_tag: "".to_string() },
            subprotocol_versions: Vec::new(),
            bandwidth_info: Vec::new(),
            exit_port_information: Vec::new()
        })
    )
);

named!(router_addr<(TorAddress,u16)>,
    do_parse!(
        tag!("a")                       >>
        space                           >>
        addr: alt!(toraddr4 | toraddr6) >>
        tag!(":")                       >>
        port: decimal_u16               >>
        newline                         >>
        ((addr, port))
    )
);

named!(router_status_flags<Vec<Flag>>,
    do_parse!(
        tag!("s")                                            >>
        space                                                >>
        r: separated_nonempty_list_complete!(sp, known_flag) >>
        newline                                              >>
        (r)
    )
);

named!(router_version<Version>,
    do_parse!(
        tag!("v")                 >>
        space                     >>
        is_not!(WHITESPACE_CHARS) >>
        space                     >>
        v: version                >>
        newline                   >>
        (v)
    )
);

named!(router_protocols<Vec<ProtocolVersion>>,
    do_parse!(
        tag!("pr")                                                >>
        space                                                     >>
        r: separated_nonempty_list_complete!(sp,protocol_version) >>
        newline                                                   >>
        (r)
    )
);

named!(router_exitinfo<Vec<PortInfo>>,
    do_parse!(
        tag!("p") >>
        sp >>
        r: alt!(accept_rules | reject_rules) >>
        newline >>
        (r)
    )
);

named!(router_bandwidth<Vec<BandwidthData>>,
    do_parse!(
        tag!("w")                                                >>
        space                                                    >>
        r: separated_nonempty_list_complete!(sp, bandwidth_info) >>
        newline                                                  >>
        (r)
    )
);

named!(bandwidth_info<BandwidthData>,
    alt!(
        do_parse!(tag!("Bandwidth=") >> v: decimal_u64 >> (Estimate(v))) |
        do_parse!(tag!("Measured=") >> v: decimal_u64 >> (Measured(v)))  |
        do_parse!(tag!("Unmeasured=1") >> (Unmeasured))                  |
        do_parse!(o: other_bwdata >> tag!("=") >> v:decimal_i64 >>
                  (UnknownBandwidthData(o,v)))
    )
);

named!(other_bwdata<String>, map_opt!(alphanumeric, force_string));

//------------------------------------------------------------------------------
//
// Section 4: The end. Starts with a weird part with bandwidth weights, and
// then jumps into a list of signatures until we're done.
//
//------------------------------------------------------------------------------

named!(directory_footer<()>,
    do_parse!(
        tag!("directory-footer") >>
        newline                  >>
        (())
    )
);

named!(bandwidth_weights<HashMap<String,i32>>,
    do_parse!(
        tag!("bandwidth-weights")                               >>
        space                                                   >>
        vs: separated_nonempty_list!(sp,bandwidth_weight_value) >>
        newline                                                 >>
        (HashMap::from_iter(vs))
    )
);

named!(bandwidth_weight_value<(String,i32)>,
    do_parse!(
        w: bandwidth_weight >>
        tag!("=")           >>
        v: decimal_i32      >>
        (w, v)
    )
);

named!(bandwidth_weight<String>,
    map_opt!(alt!(tag!("Wgg") | tag!("Wgm") | tag!("Wgd") |
                  tag!("Wmg") | tag!("Wmm") | tag!("Wme") | tag!("Wmd") |
                  tag!("Weg") | tag!("Wem") | tag!("Wee") | tag!("Wed") |
                  tag!("Wgb") | tag!("Wmb") | tag!("Web") | tag!("Wdb") |
                  tag!("Wbg") | tag!("Wbm") | tag!("Wbe") | tag!("Wbd")),
             force_string));

named!(directory_signatures<Vec<DirectorySignature>>,
    many1!(complete!(directory_signature)));

named!(directory_signature<DirectorySignature>,
    do_parse!(
        tag!("directory-signature") >>
        algo: signature_algo        >>
        // FIXME: algorithm case
        space                       >>
        i: hexbytes                 >>
        space                       >>
        d: hexbytes                 >>
        newline                     >>
        s: signature                >>
        newline                     >>
        (DirectorySignature {
            identity: i,
            algorithm: algo,
            signing_key_digest: d,
            signature: s
        })
    )
);

named!(signature_algo<SignatureAlgorithm>,
    map!(opt!(do_parse!(sp >> a: algo >> (a))),
         |v| match v {
                None => SigSHA1,
                Some(v) => v
         }));

named!(algo<SignatureAlgorithm>,
    alt!(do_parse!(tag!("sha1")   >> (SigSHA1))    |
         do_parse!(tag!("sha256") >> (SigSHA256))));

named!(signature<Vec<u8>>,
    do_parse!(
        tag!("-----BEGIN SIGNATURE-----")                        >>
        newline                                                  >>
        vs: separated_nonempty_list_complete!(newline,base64val) >>
        newline                                                  >>
        tag!("-----END SIGNATURE-----")                          >>
        (vs.concat())
    )
);

//------------------------------------------------------------------------------
//
// Testing!!!
//
//------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::{NaiveDate,NaiveDateTime,NaiveTime};
    use std::net::Ipv4Addr;
    use super::*;

    fn done<T>(result: T) -> IResult<&'static[u8],T> {
        IResult::Done(&b""[..],result)
    }

    #[test]
    fn protocols_work() {
        assert_eq!(protocol_version(b"DirCache=1"),
                   done(ProtocolVersion {
                           protocol: Protocol::DirCache,
                           versions: vec![1] }));
        assert_eq!(protocol_version(b"Cons=1-2"),
                   done(ProtocolVersion{
                           protocol: Protocol::ConsensusDoc,
                           versions: vec![1,2] }));
        assert_eq!(protocol_version(b"Desc=1-2"),
                   done(ProtocolVersion {
                           protocol: Protocol::Descriptor,
                           versions: vec![1,2] }));
        assert_eq!(protocol_version(b"HSDir=1"),
                   done(ProtocolVersion {
                           protocol: Protocol::HiddenServiceDir,
                           versions: vec![1] }));
        assert_eq!(protocol_version(b"HSIntro=3"),
                   done(ProtocolVersion {
                           protocol: Protocol::HiddenServiceIntro,
                           versions: vec![3] }));
        assert_eq!(protocol_version(b"HSRend=1"),
                   done(ProtocolVersion {
                           protocol: Protocol::HiddenServiceRendezvous,
                           versions: vec![1] }));
        assert_eq!(protocol_version(b"Link=4"),
                   done(ProtocolVersion {
                           protocol: Protocol::Link,
                           versions: vec![4] }));
        assert_eq!(protocol_version(b"LinkAuth=1"),
                   done(ProtocolVersion {
                           protocol: Protocol::LinkAuth,
                           versions: vec![1] }));
        assert_eq!(protocol_version(b"LinkAuth=1,3"),
                   done(ProtocolVersion {
                           protocol: Protocol::LinkAuth,
                           versions: vec![1,3] }));
        assert_eq!(protocol_version(b"Microdesc=1-2"),
                   done(ProtocolVersion {
                           protocol: Protocol::MicroDescriptor,
                           versions: vec![1,2] }));
        assert_eq!(protocol_version(b"Microdesc=1-2,4"),
                   done(ProtocolVersion {
                           protocol: Protocol::MicroDescriptor,
                           versions: vec![1,2,4] }));
        assert_eq!(protocol_version(b"Relay=2"),
                   done(ProtocolVersion {
                           protocol: Protocol::Relay,
                           versions: vec![2] }));
    }

    #[test]
    fn parameters_work() {
        assert_eq!(parameter(b"CircuitPriorityHalflifeMsec=30000"),
                   done(CircuitHalfLife(30000)));
        assert_eq!(parameter(b"Support022HiddenServices=0"),
                   done(Support022HiddenServices(0)));
        assert_eq!(parameter(b"pb_mincircs=-1"),
                   done(PBMinCircuits(-1)));
    }

    macro_rules! make_version {
        ($($v: expr),* ; $s: expr) =>
            (Version{ version_numbers: vec![$($v),*],
                      version_tag: $s.to_string() });
        ($($v: expr),*) =>
            (make_version!($($v),*;""))
    }

    #[test]
    fn version_works() {
        assert_eq!(version(b"0.2.4.27"), done(make_version!(0,2,4,27)));
        assert_eq!(version(b"0.3.0.3-alpha"),
                   done(make_version!(0,3,0,3;"alpha")));
        assert_eq!(version(b"0.3.0.5-rc"), done(make_version!(0,3,0,5;"rc")));
        assert_eq!(version(b"0.2.7.1-alpha-dev"),
                   done(make_version!(0,2,7,1;"alpha-dev")));
    }

    #[test]
    fn hostname_works() {
        assert_eq!(hostname(b"dannenberg.torauth.de"),
                   done("dannenberg.torauth.de".to_string()));
        assert_eq!(hostname(b"199.254.238.53"),
                   done("199.254.238.53".to_string()));
    }

    #[test]
    fn dirsource_works() {
        assert_eq!(directory_source(b"dir-source dannenberg 0232AF901C31A04EE9848595AF9BB7620D4C5B2E dannenberg.torauth.de 193.23.244.244 80 443\ncontact Andreas Lehner\nvote-digest 471E342643DECD585F8A37058B2215A2ADF518B0"),
                   done(DirectorySource {
                          name: "dannenberg".to_string(),
                          identity: vec![0x02,0x32,0xAF,0x90,
                                         0x1C,0x31,0xA0,0x4E,
                                         0xE9,0x84,0x85,0x95,
                                         0xAF,0x9B,0xB7,0x62,
                                         0x0D,0x4C,0x5B,0x2E],
                          hostname: "dannenberg.torauth.de".to_string(),
                          address: Ipv4Addr::new(193,23,244,244),
                          dirport: 80,
                          orport: 443,
                          contact_info: OsString::from("Andreas Lehner"),
                          vote_digest: vec![0x47,0x1E,0x34,0x26,
                                            0x43,0xDE,0xCD,0x58,
                                            0x5F,0x8A,0x37,0x05,
                                            0x8B,0x22,0x15,0xA2,
                                            0xAD,0xF5,0x18,0xB0]
                          }));
        assert_eq!(directory_source(b"dir-source tor26 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38 86.59.21.38 80 443\ncontact Peter Palfrader\nvote-digest A178748E4F39B9DAC2D373E990388AA32BE6DE6E"),
                   done(DirectorySource {
                          name: "tor26".to_string(),
                          identity: vec![0x14,0xC1,0x31,0xDF,
                                         0xC5,0xC6,0xF9,0x36,
                                         0x46,0xBE,0x72,0xFA,
                                         0x14,0x01,0xC0,0x2A,
                                         0x8D,0xF2,0xE8,0xB4],
                          hostname: "86.59.21.38".to_string(),
                          address: Ipv4Addr::new(86,59,21,38),
                          dirport: 80,
                          orport: 443,
                          contact_info: OsString::from("Peter Palfrader"),
                          vote_digest: vec![0xA1,0x78,0x74,0x8E,
                                            0x4F,0x39,0xB9,0xDA,
                                            0xC2,0xD3,0x73,0xE9,
                                            0x90,0x38,0x8A,0xA3,
                                            0x2B,0xE6,0xDE,0x6E]
                        }));
    }

    #[test]
    fn router_status_flags_works() {
        assert_eq!(router_status_flags(b"s Fast Guard HSDir Running Stable V2Dir Valid\n"),
                   done(vec![Fast,Guard,HSDir,Running,Stable,V2Dir,Valid]));
        assert_eq!(router_status_flags(b"s Fast Running Stable Valid\n"),
                   done(vec![Fast,Running,Stable,Valid]));
    }

    #[test]
    fn router_version_works() {
        assert_eq!(router_version(b"v Tor 0.2.9.10\n"),
                   done(make_version!(0,2,9,10)));
        assert_eq!(router_version(b"v Tor 0.3.1.3-alpha\n"),
                   done(make_version!(0,3,1,3;"alpha")))
    }

    #[test]
    fn router_protocols_works() {
        assert_eq!(router_protocols(b"pr Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2\n"),
                   done(vec![ProtocolVersion { protocol: Protocol::ConsensusDoc,
                                               versions: vec![1,2] },
                             ProtocolVersion { protocol: Protocol::Descriptor,
                                               versions: vec![1,2] },
                             ProtocolVersion { protocol: Protocol::DirCache,
                                               versions: vec![1] },
                             ProtocolVersion { protocol: Protocol::HiddenServiceDir,
                                               versions: vec![1] },
                             ProtocolVersion { protocol: Protocol::HiddenServiceIntro,
                                               versions: vec![3] },
                             ProtocolVersion { protocol: Protocol::HiddenServiceRendezvous,
                                               versions: vec![1] },
                             ProtocolVersion { protocol: Protocol::Link,
                                               versions: vec![1,2,3,4] },
                             ProtocolVersion { protocol: Protocol::LinkAuth,
                                               versions: vec![1] },
                             ProtocolVersion { protocol: Protocol::MicroDescriptor,
                                               versions: vec![1,2] },
                             ProtocolVersion { protocol: Protocol::Relay,
                                               versions: vec![1,2] }]));
    }

    #[test]
    fn router_exitinfo_works() {
        assert_eq!(router_exitinfo(b"p reject 1-65535\n"),
                   done(vec![PortInfo::RejectRange(1,65535)]));
        assert_eq!(router_exitinfo(b"p accept 22,53,80,443\n"),
                   done(vec![PortInfo::AcceptPort(22),
                             PortInfo::AcceptPort(53),
                             PortInfo::AcceptPort(80),
                             PortInfo::AcceptPort(443)]));
        assert_eq!(router_exitinfo(b"p reject 25,119,135-139,445,563,1214,4661-4666,6346-6429,6699,6881-6999\n"),
                   done(vec![PortInfo::RejectPort(25),
                             PortInfo::RejectPort(119),
                             PortInfo::RejectRange(135,139),
                             PortInfo::RejectPort(445),
                             PortInfo::RejectPort(563),
                             PortInfo::RejectPort(1214),
                             PortInfo::RejectRange(4661,4666),
                             PortInfo::RejectRange(6346,6429),
                             PortInfo::RejectPort(6699),
                             PortInfo::RejectRange(6881,6999)]));
    }

    #[test]
    fn router_bandwidth_works() {
        assert_eq!(bandwidth_info(b"Bandwidth=1520"), done(Estimate(1520)));
        assert_eq!(router_bandwidth(b"w Bandwidth=1520\n"),
                   done(vec![Estimate(1520)]));
        assert_eq!(router_bandwidth(b"w Bandwidth=155\n"),
                   done(vec![Estimate(155)]));
        assert_eq!(router_bandwidth(b"w Bandwidth=0 Unmeasured=1\n"),
                   done(vec![Estimate(0), Unmeasured]));
        assert_eq!(router_bandwidth(b"w Bandwidth=20 Unmeasured=1\n"),
                   done(vec![Estimate(20), Unmeasured]));
    }

    #[test]
    fn router_line_works() {
        assert_eq!(router_header(b"r seele AAoQ1DAR6kkoo19hBAX5K0QztNw Kdm6LYzjnc4MvAp59IwiFLSwdos 2017-06-15 15:11:30 67.161.31.147 9001 0\n"),
                   done(RouterInfo {
                      nickname: "seele".to_string(),
                      identity: vec![0, 10, 16, 212, 48, 17, 234, 73, 40, 163, 95, 97, 4, 5, 249, 43, 68, 51, 180, 220],
                      digest: vec![41, 217, 186, 45, 140, 227, 157, 206, 12, 188, 10, 121, 244, 140, 34, 20, 180, 176, 118, 139],
                      publication_time: DateTime::from_utc(NaiveDateTime::new(NaiveDate::from_ymd(2017,6,15), NaiveTime::from_hms(15,11,30)),Utc),
                      main_address: Ipv4Addr::new(67,161,31,147),
                      main_or_port: 9001,
                      dir_port: 0,
                      other_addresses: Vec::new(),
                      flags: Vec::new(),
                      version: Version{ version_numbers: Vec::new(),
                                        version_tag: "".to_string() },
                      subprotocol_versions: Vec::new(),
                      bandwidth_info: Vec::new(),
                      exit_port_information: Vec::new()
                }))
    }

    #[test]
    fn known_flags_stuff() {
        assert_eq!(known_flag(b"NoEdConsensus"), done(NoEdConsensus));
        assert_eq!(known_flag(b"V2Dir"), done(V2Dir));
        assert_eq!(known_flags(b"known-flags Authority BadExit Exit Fast Guard HSDir NoEdConsensus Running Stable V2Dir Valid\n"),
                   done(vec![Authority,BadExit,Exit,Fast,Guard,HSDir,NoEdConsensus,Running,Stable,V2Dir,Valid]));
    }
}
