use base64::DecodeError;
use chrono::{DateTime,Utc};
use nom::*;
use ring::digest;
use parsing_utils::{PortInfo,ProtocolVersion,TorAddress,
                    nickname, ip4addr, toraddr4, toraddr6,
                    decimal_u8, decimal_u16, decimal_u64, protocol_version,
                    base64_noequals, base64_line, generic_string, datetime,
                    hexbytes, accept_rules, reject_rules,
                    pem_signature, pem_public_key, concat_vecs};
use ring::digest::{SHA256, digest};
use ring::signature::{ED25519, verify};
use std::ffi::OsString;
use std::net::Ipv4Addr;
use tor_crypto::{Ed25519Certificate,Ed25519CertType,CertKeyType,RSAPublicKey,pkcs1_verify};
use types::*;
use untrusted::Input;

pub fn parse_server_descriptors(i: &[u8])
    -> Result<Vec<ServerDescriptor>,ServerDescParseErr>
{
    let mut output = Vec::new();
    let mut input  = i;

    loop {
        match parse_server_descriptor(input) {
            Err(e)          => return Err(e),
            Ok((b"", v))    => { output.push(v); return Ok(output) }
            Ok((ninput, v)) => { output.push(v); input = ninput    }
        }
    }
}

fn translate_error(e: ErrorKind<u32>) -> ServerDescParseErr {
    match e {
        _ => ServerDescParseErr::ParserError(e)
    }
}

macro_rules! nomtry {
    ( $i: expr ) => {
        match $i {
            IResult::Done(rest, v) =>
                (rest, v),
            IResult::Incomplete(i) =>
                return Result::Err(ServerDescParseErr::NotEnoughData),
            IResult::Error(e)      =>
                return Result::Err(ServerDescParseErr::ParserError(e))
        }
    }
}

macro_rules! parse_andr {
    ( $i: expr, $c: expr, $f: expr) => {
        match $i($c) {
            IResult::Done(rest, v) => {
                $c = rest;
                match $f(v) {
                    Ok(()) => {  }
                    Err(e) => return Err(e)
                }
            }
            IResult::Incomplete(_) => {}
            IResult::Error(_)      => {}
        }
    }
}

macro_rules! parse_and {
    ( $i: expr, $c: expr, $f: expr) => {
        match $i($c) {
            IResult::Done(rest, v) => {
                $c = rest;
                $f(v);
            }
            IResult::Incomplete(_) => {}
            IResult::Error(_)      => {}
        }
    }
}

macro_rules! any_number_fun {
    ( $p: expr, $c: expr, $k: expr, $fun: expr) => {
        match $p($c) {
            IResult::Done(rest, v) => {
                $c = rest;
                $fun(v);
                $k = true;
            }
            IResult::Incomplete(_) => {}
            IResult::Error(_)      => {}
        }
    }
}

macro_rules! any_number {
    ( $p: expr, $c: expr, $k: expr, $fld: expr) => {
        any_number_fun!($p, $c, $k, |v| { $fld.push(v) })
    }
}

macro_rules! at_most_once_norm {
    ( $p: expr, $c: expr, $k: expr, $fld: expr, $fun: expr) => {
        match $fld {
            Some(_) => { }
            None    => any_number_fun!($p, $c, $k, |v| $fun(v))
        }
    }
}

macro_rules! at_most_once {
    ( $p: expr, $c: expr, $k: expr, $fld: expr) => {
        at_most_once_norm!($p, $c, $k, $fld, |v| { $fld = Some(v); })
    }
}

macro_rules! at_most_onceo {
    ( $p: expr, $c: expr, $k: expr, $fld: expr) => {
        at_most_once_norm!($p, $c, $k, $fld, |v| {
            match v {
                Some(v) => { $fld = Some(v); }
                Noen    => {                 }
            }
        })
    }
}

macro_rules! at_most_oncer {
    ( $p: expr, $c: expr, $k: expr, $fld: expr) => {
        at_most_once_norm!($p, $c, $k, $fld, |v| {
            match v {
                Result::Ok(v)  => { $fld = Some(v); }
                Result::Err(_) => {                 }
            }
        })
    }
}

macro_rules! exactly_once {
    ( $e: expr ) => {
        match $e {
            Some(_) => { }
            None    =>
                return Result::Err(ServerDescParseErr::MissingField)
        }
    }
}

pub fn parse_server_descriptor(i: &[u8])
    -> Result<(&[u8],ServerDescriptor),ServerDescParseErr>
{
    let (mut cur_input, mut cur) = nomtry!(router(i));
    let mut go_on = true;

    parse_andr!(identity_ed25519, cur_input, |c: Option<Ed25519Certificate>| {
        match c {
            None =>
                Err(ServerDescParseErr::WrongEd25519KeyType),
            Some(cert) => {
                if cert.cert_type != Ed25519CertType::SigningKeyWithIdentity {
                    Err(ServerDescParseErr::WrongEd25519KeyType)
                } else {
                    cur.ed25519_identity_cert = Some(cert);
                    Ok(())
                }
            }
        }
    });

    while go_on {
        go_on = false;
        at_most_once!( master_ed25519,       cur_input,go_on,cur.ed25519_master_key);
        at_most_once!( bandwidth,            cur_input,go_on,cur.bandwidth);
        at_most_once!( platform,             cur_input,go_on,cur.platform);
        at_most_once!( published,            cur_input,go_on,cur.published);
        at_most_once!( fingerprint,          cur_input,go_on,cur.fingerprint);
        at_most_once!( hibernating,          cur_input,go_on,cur.hibernating);
        at_most_once!( uptime,               cur_input,go_on,cur.uptime);
        at_most_oncer!(onion_key,            cur_input,go_on,cur.onion_key);
        at_most_oncer!(onion_crosscert,      cur_input,go_on,cur.onion_crosscert);
        at_most_once!( ntor_onion_key,       cur_input,go_on,cur.ed25519_onion_key);
        at_most_onceo!(ntor_crosscert,       cur_input,go_on,cur.ntor_crosscert);
        at_most_oncer!(signing_key,          cur_input,go_on,cur.signing_key);
        any_number!(   exit_rule,            cur_input,go_on,cur.exit_policy);
        at_most_once!( ip6_policy,           cur_input,go_on,cur.exit_policy_ip6);
        at_most_once!( contact,              cur_input,go_on,cur.contact);
        at_most_once!( family,               cur_input,go_on,cur.family_names);
        at_most_once!( read_history,         cur_input,go_on,cur.read_history);
        at_most_once!( write_history,        cur_input,go_on,cur.write_history);
        at_most_once!( eventdns,             cur_input,go_on,cur.eventdns);
        at_most_once!( caches_extra_info,    cur_input,go_on,cur.caches_extra_info);
        at_most_once!( extra_info_digest,    cur_input,go_on,cur.extra_info_digest);
        at_most_once!( hidden_service_dir,   cur_input,go_on,cur.stores_hidden_service_descriptors);
        at_most_once!( protocols,            cur_input,go_on,cur.protocols);
        at_most_once!( allow_single_hops,    cur_input,go_on,cur.allows_single_hop_exits);
        any_number!(   or_address,           cur_input,go_on,cur.other_addresses);
        at_most_once!( tunnelled_dir_server, cur_input,go_on,cur.accepts_tunneled_dir_requests);
        at_most_once!( proto,                cur_input,go_on,cur.protocol_versions);
    }

    let pre_signature_input = cur_input;
    parse_and!(router_sig_ed25519, cur_input, |sig| {
        cur.ed25519_router_sig = Some(sig);
    });

    let (rest_input, sig) = nomtry!(router_sig(cur_input));

    exactly_once!(cur.bandwidth);
    exactly_once!(cur.published);
    exactly_once!(cur.onion_key);
    exactly_once!(cur.signing_key);

    // if an ed25519 identity is present, then a bunch of other fields become
    // required.
    if let &Some(ref masterkey) = &cur.ed25519_master_key {
        exactly_once!(cur.onion_crosscert);
        exactly_once!(cur.ntor_crosscert);
        exactly_once!(cur.ed25519_router_sig);
        // in addition, the master key provided must match the subkey provided
        // in the ed25519 identity key.
        if let &Some(ref idcert) = &cur.ed25519_identity_cert {
            if !idcert.subkey_matches(&masterkey) {
                return Err(ServerDescParseErr::Ed25519KeyMatchFailure);
            }
            // Hash the stuff in the message for the signature
            let basestr = b"Tor router descriptor signature v1";
            let sigpart = &i[0 .. (i.len() - pre_signature_input.len() + 19)];
            let mut buffer = Vec::new();
            buffer.extend_from_slice(basestr);
            buffer.extend_from_slice(sigpart);
            let digest = digest(&SHA256, &buffer);
            let bodym = Input::from(digest.as_ref());
            // then check the signature
            let signkey = match &idcert.data {
                              &CertKeyType::Ed25519(ref v) => v,
                              _ => return Err(ServerDescParseErr::WrongEd25519KeyType)
                          };
            let master_key = Input::from(&signkey.n);
            let sig = cur.ed25519_router_sig.unwrap();
            println!("siglen: {}", sig.len());
            let edsig = Input::from(&sig);
            let check = verify(&ED25519, master_key, bodym, edsig);
            println!("check: {:?}", check);
            if check.is_err() {
                return Err(ServerDescParseErr::Ed25519SignatureFailured);
            }
        }
    }

    if cur.onion_crosscert.is_some() {
        // Compute the vector for onion-key-crosscert, which is:
        //   - A SHA1 hash of the RSA identity key (signing-key, 20 bytes)
        //   - The ed25519 identity key, or 32 bytes of 0
        // This isn't mandatory, unless the ed25519 key is provided.
        let mut crosscert = Vec::new();
        let identity_key_hash = digest::digest(&digest::SHA1,&cur.signing_key.clone().unwrap());
        let mut ed25519_or_zero = cur.ed25519_master_key.clone().unwrap_or(vec![0; 32]);
        crosscert.extend_from_slice(identity_key_hash.as_ref());
        crosscert.append(&mut ed25519_or_zero);
        let onion_key = match RSAPublicKey::decode(&cur.onion_key.clone().unwrap()) {
                            None =>
                                return Err(ServerDescParseErr::OnionCrossCertCheckFailed),
                            Some(v) =>
                                v
                        };
        if !pkcs1_verify(&onion_key, &[], &crosscert, &cur.onion_crosscert.unwrap()) {
            return Err(ServerDescParseErr::OnionCrossCertCheckFailed);
        }
    }

    {
        let signing_key = match RSAPublicKey::decode(&cur.signing_key.clone().unwrap()) {
                             None =>
                                 return Err(ServerDescParseErr::SignatureCheckFailed),
                             Some(v) =>
                                 v
                          };
        let body = &i[0 .. (i.len() - cur_input.len() + 17)];
        let body_hash = digest::digest(&digest::SHA1, body);
        if !pkcs1_verify(&signing_key, &[], body_hash.as_ref(), &sig) {
            return Err(ServerDescParseErr::SignatureCheckFailed);
        }

    }

    Result::Ok((rest_input, ServerDescriptor {
        nickname: cur.nickname,
        address: cur.address,
        or_port: cur.or_port,
        dir_port: cur.dir_port,
        ed25519_identity_cert: cur.ed25519_identity_cert,
        ed25519_master_key: cur.ed25519_master_key,
        bandwidth: cur.bandwidth.unwrap(), // FIXME: Change these unwraps to error cases
        platform: cur.platform,
        published: cur.published.unwrap(),
        fingerprint: cur.fingerprint,
        hibernating: cur.hibernating,
        uptime: cur.uptime.unwrap_or(0),
        onion_key: cur.onion_key.unwrap(),
        ed25519_onion_key: cur.ed25519_onion_key,
        signing_key: cur.signing_key.unwrap(),
        exit_policy: cur.exit_policy,
        exit_policy_ip6: cur.exit_policy_ip6.unwrap_or(vec![PortInfo::RejectRange(1,65535)]),
        contact: cur.contact.unwrap_or(OsString::new()),
        family_names: cur.family_names.unwrap_or(Vec::new()),
        read_history: cur.read_history,
        write_history: cur.write_history,
        caches_extra_info: cur.caches_extra_info.unwrap_or(false),
        extra_info_digest: cur.extra_info_digest,
        stores_hidden_service_descriptors: cur.stores_hidden_service_descriptors,
        allows_single_hop_exits: cur.allows_single_hop_exits.unwrap_or(false),
        other_addresses: cur.other_addresses,
        accepts_tunneled_dir_requests: cur.accepts_tunneled_dir_requests.unwrap_or(false),
        protocol_versions: cur.protocol_versions.unwrap_or(Vec::new())
    }))
}

struct ParsingServerDescriptor {
    nickname: String,
    address: Ipv4Addr,
    or_port: Option<u16>,
    dir_port: Option<u16>,
    ed25519_identity_cert: Option<Ed25519Certificate>,
    ed25519_master_key: Option<Vec<u8>>,
    bandwidth: Option<BandwidthMeasurement>,
    platform: Option<OsString>,
    published: Option<DateTime<Utc>>,
    fingerprint: Option<Vec<u8>>,
    hibernating: Option<bool>,
    uptime: Option<u64>,
    onion_key: Option<Vec<u8>>,
    ed25519_onion_key: Option<Vec<u8>>,
    signing_key: Option<Vec<u8>>,
    exit_policy: Vec<ExitPolicyRule>,
    exit_policy_ip6: Option<Vec<PortInfo>>,
    contact: Option<OsString>,
    family_names: Option<Vec<FamilyDescriptor>>,
    read_history: Option<HistoryInformation>,
    write_history: Option<HistoryInformation>,
    eventdns: Option<bool>,
    caches_extra_info: Option<bool>,
    extra_info_digest: Option<(Vec<u8>,Option<Vec<u8>>)>,
    stores_hidden_service_descriptors: Option<Vec<u8>>,
    protocols: Option<()>,
    allows_single_hop_exits: Option<bool>,
    other_addresses: Vec<(TorAddress, u16)>,
    accepts_tunneled_dir_requests: Option<bool>,
    protocol_versions: Option<Vec<ProtocolVersion>>,
    //
    onion_crosscert: Option<Vec<u8>>,
    ntor_crosscert: Option<(bool, Ed25519Certificate)>,
    ed25519_router_sig: Option<Vec<u8>>
}

named!(router<ParsingServerDescriptor>,
    do_parse!(
        tag!("router") >> space   >>
        n: nickname    >> space   >>
        a: ip4addr     >> space   >>
        o: decimal_u16 >> space   >>
           decimal_u16 >> space   >>
        d: decimal_u16 >> newline >>
        (ParsingServerDescriptor {
            nickname: n,
            address: a,
            or_port: if o == 0 { None } else { Some(o) },
            dir_port: if d == 0 { None } else { Some(d) },
            ed25519_identity_cert: None,
            ed25519_master_key: None,
            bandwidth: None,
            platform: None,
            published: None,
            fingerprint: None,
            hibernating: None,
            uptime: None,
            onion_key: None,
            ed25519_onion_key: None,
            signing_key: None,
            exit_policy: Vec::new(),
            exit_policy_ip6: None,
            contact: None,
            family_names: None,
            read_history: None,
            write_history: None,
            eventdns: None,
            caches_extra_info: None,
            extra_info_digest: None,
            stores_hidden_service_descriptors: None,
            protocols: None,
            allows_single_hop_exits: None,
            other_addresses: Vec::new(),
            accepts_tunneled_dir_requests: None,
            protocol_versions: None,
            onion_crosscert: None,
            ntor_crosscert: None,
            ed25519_router_sig: None
        })
    )
);

named!(identity_ed25519<Option<Ed25519Certificate>>,
    do_parse!(
        tag!("identity-ed25519")             >> newline >>
        c: ed25519_certificate               >>
        (c)
    )
);

named!(master_ed25519<Vec<u8>>,
    do_parse!(
        tag!("master-key-ed25519") >> space   >>
        m: base64_noequals         >> newline >>
        (m)
    )
);

named!(bandwidth<BandwidthMeasurement>,
    do_parse!(
        tag!("bandwidth")  >> space   >>
        a: decimal_u64     >> space   >>
        b: decimal_u64     >> space   >>
        o: decimal_u64     >> newline >>
        (BandwidthMeasurement {
            average: a,
            burst: b,
            observed: o
        })
    )
);

named!(platform<OsString>,
    do_parse!(
        tag!("platform")   >> space   >>
        p: generic_string  >> newline >>
        (p)
    )
);

named!(published<DateTime<Utc>>,
    do_parse!(
        tag!("published") >> space   >>
        d: datetime       >> newline >>
        (d)
    )
);

named!(fingerprint<Vec<u8>>,
    do_parse!(
        tag!("fingerprint") >> space   >>
        fp: spaced_hexbytes >> newline >>
        (fp)
    )
);

named!(hibernating<bool>,
    do_parse!(
        tag!("hibernating") >> space   >>
        v: decimal_u8       >> newline >>
        (v > 0)
    )
);

named!(uptime<u64>,
    do_parse!(
        tag!("uptime") >> space   >>
        t: decimal_u64 >> newline >>
        (t)
    )
);

named!(onion_key<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        tag!("onion-key") >> newline >>
        k: pem_public_key >>
        (k)
    )
);

named!(onion_crosscert<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        tag!("onion-key-crosscert") >> newline >>
        c: crosscert                >>
        (c)
    )
);

named!(ntor_onion_key<Vec<u8>>,
    do_parse!(
        tag!("ntor-onion-key") >> space   >>
        k: base64_noequals     >> newline >>
        (k)
    )
);

named!(ntor_crosscert<Option<(bool, Ed25519Certificate)>>,
    do_parse!(
        tag!("ntor-onion-key-crosscert")     >> space   >>
        b: decimal_u8                        >> newline >>
        c: ed25519_certificate               >>
        (c.map(|cert| (b > 0, cert)))
    )
);

named!(signing_key<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        tag!("signing-key")      >> newline >>
        k: pem_public_key        >>
        (k)
    )
);

named!(exit_rule<ExitPolicyRule>,
    do_parse!(
        ar: accept_reject        >> space     >>
        addrm: exit_rule_addr    >> tag!(":") >>
        r: exit_rule_range       >> newline   >>
        ({ let (addr, mask) = addrm;
           let (strt, end)  = r;
           ExitPolicyRule {
               address: addr,
               mask: mask,
               port_start: strt,
               port_end: end,
               rule: ar
           }})
    )
);

named!(ip6_policy<Vec<PortInfo>>,
    do_parse!(
        tag!("ipv6-policy")                  >> space   >>
        r: alt!(accept_rules | reject_rules) >> newline >>
        (r)
    )
);

named!(router_sig_ed25519<Vec<u8>>,
    do_parse!(
        tag!("router-sig-ed25519") >> space   >>
        sig: base64_noequals       >> newline >>
        (sig)
    )
);

named!(router_sig<Vec<u8>>,
    do_parse!(
        tag!("router-signature") >> newline >>
        sig: pem_signature       >>
        (sig.unwrap()) // FIXME
    )
);

named!(contact<OsString>,
    do_parse!(
        tag!("contact")   >> space   >>
        s: generic_string >> newline >>
        (s)
    )
);

named!(family<Vec<FamilyDescriptor>>,
    do_parse!(
        tag!("family")                                            >> space   >>
        n: separated_nonempty_list_complete!(space, family_descr) >> newline >>
        (n)
    )
);

named!(read_history<HistoryInformation>,
    do_parse!(
        tag!("read-history")  >> space >> hi: history_info >>
        (hi)
    )
);

named!(write_history<HistoryInformation>,
    do_parse!(
        tag!("write-history")  >> space >> hi: history_info >>
        (hi)
    )
);

named!(eventdns<bool>,
    do_parse!(
        tag!("eventdns") >> space >> b: decimal_u8 >> (b > 0)
    )
);

named!(caches_extra_info<bool>,
    do_parse!(
        tag!("caches-extra-info") >> newline >>
        (true)
    )
);

named!(extra_info_digest<(Vec<u8>, Option<Vec<u8>>)>,
    do_parse!(
        tag!("extra-info-digest") >> space >>
        sha1: hexbytes >>
        sha256: opt!(do_parse!(space >> b: base64_noequals >> (b))) >>
        newline >>
        (sha1, sha256)
    )
);

named!(hidden_service_dir<Vec<u8>>,
    do_parse!(
        tag!("hidden-service-dir") >>
        d: many0!(do_parse!(space >> v: decimal_u8 >> (v))) >>
        newline >>
        (d)
    )
);

named!(protocols<()>,
    do_parse!(
        tag!("protocols")                                    >> space   >>
        tag!("Link")                                         >> space   >>
        separated_nonempty_list_complete!(space, decimal_u8) >> space   >>
        tag!("Circuit")                                      >> space   >>
        separated_nonempty_list_complete!(space, decimal_u8) >> newline >>
        (())
    )
);

named!(allow_single_hops<bool>,
    do_parse!(
        tag!("allow-single-hop-exits") >> newline >> (true)
    )
);

named!(or_address<(TorAddress, u16)>,
    do_parse!(
        tag!("or-address")                        >> space          >>
        a: alt!(toraddr4 | toraddr6) >> tag!(":") >> p: decimal_u16 >>
        newline                                   >>
        ((a, p))
    )
);

named!(tunnelled_dir_server<bool>,
    do_parse!(
        tag!("tunnelled-dir-server") >> newline >> (true)
    )
);

named!(proto<Vec<ProtocolVersion>>,
    do_parse!(
        tag!("proto") >> space >>
        pvs: separated_nonempty_list_complete!(sp, protocol_version) >>
        newline >>
        (pvs)
    )
);

named!(history_info<HistoryInformation>,
    do_parse!(
        d: datetime >> space >>
        tag!("(") >> ns: decimal_u64 >> space >> tag!("s)") >> space  >>
        vs: separated_nonempty_list_complete!(tag!(","), decimal_u64) >>
        newline >>
        (HistoryInformation {
            interval_nsecs: ns,
            interval_end: d,
            bandwidth_used: vs
        })
    )
);

named!(family_descr<FamilyDescriptor>,
    alt!(do_parse!(n: nickname >>
                   (FamilyDescriptor::FamilyName(n)))                       |
         do_parse!(tag!("$") >> v: hexbytes >> tag!("~") >> n: nickname >>
                   (FamilyDescriptor::FamilyIdAndName(v,n)))                |
         do_parse!(tag!("$") >> v: hexbytes >> tag!("=") >> n: nickname >>
                   (FamilyDescriptor::FamilyIdAndName(v,n)))                |
         do_parse!(tag!("$") >> v: hexbytes >>
                   (FamilyDescriptor::FamilyIdDigest(v))))
);

named!(accept_reject<AcceptReject>,
    alt!(do_parse!(tag!("accept") >> (AcceptReject::Accept)) |
         do_parse!(tag!("reject") >> (AcceptReject::Reject)))
);

named!(exit_rule_addr<(Ipv4Addr, u8)>,
    alt!(do_parse!(a: ip4addr >> tag!("/") >> m: decimal_u8 >> (a, m)) |
         do_parse!(a: ip4addr >> (a, 24))                              |
         do_parse!(tag!("*") >> (Ipv4Addr::new(0,0,0,0), 0)))
);

named!(exit_rule_range<(u16, u16)>,
    alt!(do_parse!(p1: decimal_u16 >> tag!("-") >> p2: decimal_u16 >> (p1, p2)) |
         do_parse!(p:  decimal_u16 >> (p, p))                                   |
         do_parse!(tag!("*")       >> (0, 65535))
         )
);

named!(ed25519_certificate<Option<Ed25519Certificate>>,
    do_parse!(
        tag!("-----BEGIN ED25519 CERT-----") >> newline >>
        vs: many1!(base64_line)              >>
        tag!("-----END ED25519 CERT-----")   >> newline >>
        (match concat_vecs(vs) {
            Ok(bs) => Ed25519Certificate::decode(&bs),
            Err(_) => None
        })
    )
);

named!(crosscert<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        tag!("-----BEGIN CROSSCERT-----")    >> newline >>
        vs: many1!(base64_line)              >>
        tag!("-----END CROSSCERT-----")      >> newline >>
        (concat_vecs(vs))
    )
);

named!(spaced_hexbytes<Vec<u8>>,
    map!(separated_nonempty_list_complete!(space,hexbytes), |mut vv| {
        let mut result = Vec::new();
        for v in vv.iter_mut() {
            result.append(v);
        }
        result
    })
);


#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Read;
    use std::str;
    use super::*;

    macro_rules! can_parse_lines {
        ($f: expr, $p: expr) => {
            let mut path = format!("test/server_descriptors/{}.txt", $f);
            let mut file = File::open(path).unwrap();
            let mut buffer = Vec::new();
            assert!(file.read_to_end(&mut buffer).is_ok());
            let mut curbuf: &[u8] = &buffer;

            loop {
                match $p(&curbuf) {
                    IResult::Done(b"", _) => break,
                    IResult::Done(newbuf, _) => curbuf = newbuf,
                    IResult::Incomplete(_) => {
                        match str::from_utf8(&curbuf) {
                            Err(_) => {
                                println!("Reached incomplete parsing line w/ odd UTF8: {:?}",
                                         &curbuf[0..30]);
                                assert!(false)
                            }
                            Ok(v) => {
                                println!("Reached incomplete parsing line: {}", &v[0..70]);
                                assert!(false)
                            }
                        }
                    }
                    IResult::Error(e) => {
                        match str::from_utf8(&curbuf) {
                            Err(_) => {
                                println!("Parse error ({}) w/ odd UTF8: {:?}", e, &curbuf[0..30]);
                                assert!(false)
                            }
                            Ok(v) => {
                                println!("Parse error ({}) on line: {}", e, &v[0..70]);
                                assert!(false)
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn can_parse_router_lines() {
        can_parse_lines!("router_lines", router);
    }

    #[test]
    fn can_parse_ed25519_master_line() {
        can_parse_lines!("ed25519-master", master_ed25519);
    }

    #[test]
    fn can_parse_platform_line() {
        can_parse_lines!("platform", platform);
    }

    #[test]
    fn can_parse_proto_line() {
        can_parse_lines!("proto", proto);
    }

    #[test]
    fn can_parse_published_line() {
        can_parse_lines!("published", published);
    }

    #[test]
    fn can_parse_fingerprint_line() {
        can_parse_lines!("fingerprint", fingerprint);
    }

    #[test]
    fn can_parse_uptime_line() {
        can_parse_lines!("uptime", uptime);
    }

    #[test]
    fn can_parse_bandwidth_line() {
        can_parse_lines!("bandwidth", bandwidth);
    }

    #[test]
    fn can_parse_extra_info_digest() {
        can_parse_lines!("extra-info-digest", extra_info_digest);
    }

    #[test]
    fn can_parse_hidden_service_dir() {
        can_parse_lines!("hidden-service-dir", hidden_service_dir);
    }

    #[test]
    fn can_parse_ntor_onion_key_line() {
        can_parse_lines!("ntor-onion-key", ntor_onion_key);
    }

    #[test]
    fn can_parse_tunneled_line() {
        can_parse_lines!("tunnelled", tunnelled_dir_server);
    }

    #[test]
    fn can_parse_router_ed25519_sig() {
        can_parse_lines!("router-sig-ed25519", router_sig_ed25519);
    }

    #[test]
    fn can_parse_contact_line() {
        can_parse_lines!("contact", contact);
    }

    #[test]
    fn can_parse_family_line() {
        can_parse_lines!("family", family);
    }

    #[test]
    fn can_parse_read_history_line() {
        can_parse_lines!("read-history", read_history);
    }

    #[test]
    fn can_parse_write_history_line() {
        can_parse_lines!("write-history", write_history);
    }

    #[test]
    fn can_parse_extra_info_line() {
        can_parse_lines!("caches-extra-info", caches_extra_info);
    }

    #[test]
    fn can_parse_protocols_line() {
        can_parse_lines!("protocols", protocols);
    }

    #[test]
    fn can_parse_single_hops_line() {
        can_parse_lines!("single-hops", allow_single_hops);
    }

    #[test]
    fn can_parse_ip6_rule_line() {
        can_parse_lines!("ip6-policy", ip6_policy);
    }

    #[test]
    fn can_parse_or_address_line() {
        can_parse_lines!("or-address", or_address);
    }

    #[test]
    fn can_parse_exit_rule_line() {
        can_parse_lines!("exit-rules", exit_rule);
    }

    #[test]
    fn can_parse_ed25519_identity() {
        can_parse_lines!("identity-ed25519", identity_ed25519);
    }

    #[test]
    fn can_parse_onion_key() {
        can_parse_lines!("onion-key", onion_key);
    }

    #[test]
    fn can_parse_signing_key() {
        can_parse_lines!("signing-key", signing_key);
    }

    #[test]
    fn can_parse_onion_crosscert() {
        can_parse_lines!("onion-key-crosscert", onion_crosscert);
    }

    #[test]
    fn can_parse_ntor_key_crosscert() {
        can_parse_lines!("ntor-crosscert", ntor_crosscert);
    }

    #[test]
    fn can_parse_router_sig() {
        can_parse_lines!("router-signature", router_sig);
    }

    #[test]
    fn samples_parse() {
        for entry in fs::read_dir("test/server_descriptors/").unwrap() {
            println!("entry: {:?}", entry);
            let entry = entry.unwrap();
            if entry.file_name().into_string().unwrap().starts_with("descr") {
                let mut fd = File::open(entry.path()).unwrap();
                let mut buffer = Vec::new();
                fd.read_to_end(&mut buffer);
                match parse_server_descriptor(&buffer) {
                    Result::Ok((b"", _)) => {   }
                    Result::Ok((_, _)) => {
                        println!("Partial parse for {:?}", entry.file_name());
                        assert!(false);
                    }
                    Result::Err(e) => {
                        println!("Parse error {:?} for {:?}", e, entry.file_name());
                        assert!(false);
                    }
                }
            }
        }
    }
}
