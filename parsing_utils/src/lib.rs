extern crate base64;
extern crate chrono;
extern crate nom;

use base64::DecodeError;
use chrono::{DateTime,NaiveDate,NaiveDateTime,NaiveTime,Utc};
use nom::*;
use std::ffi::OsString;
use std::net::{Ipv4Addr,Ipv6Addr};
use std::os::unix::ffi::OsStringExt;
use std::str;
use std::str::FromStr;

#[derive(Debug,Eq,PartialEq)]
pub enum PortInfo {
    AcceptPort(u16),
    RejectPort(u16),
    AcceptRange(u16,u16),
    RejectRange(u16,u16)
}

#[derive(Debug,Eq,PartialEq)]
pub enum Protocol { ConsensusDoc, Descriptor, DirCache, HiddenServiceDir,
                    HiddenServiceIntro, HiddenServiceRendezvous, Link,
                    LinkAuth, MicroDescriptor, Relay }

#[derive(Debug,Eq,PartialEq)]
pub struct ProtocolVersion {
    pub protocol: Protocol,
    pub versions: Vec<u8>
}

#[derive(Debug,Eq,PartialEq)]
pub enum TorAddress {
    Hostname(String),
    IPv4Addr(Ipv4Addr),
    IPv6Addr(Ipv6Addr)
}



pub enum BitParseResult<'a,T> {
    Continue(&'a[u8]),
    NoBits,
    BitError(T)
}

#[macro_export]
macro_rules! try_parser {
    ( $i: expr, $p:expr, $c:expr, $d:expr ) => {
        let tempval = $p($i);
        if tempval.is_done() {
            let (iprime, v) = tempval.unwrap();
            $c += 1;
            $d = v;
            return Some(iprime);
        }
    }
}

#[macro_export]
macro_rules! parser_once {
    ( $i: expr, $p: expr, $f: expr, $e: expr ) => {
        let tempval = $p($i);
        if tempval.is_done() {
            match $f {
                None => {
                    let (iprime, v) = tempval.unwrap();
                    $f = Some(v);
                    return Continue(iprime)
                }
                Some(_) => {
                    return BitError($e);
                }
            }
        }
    }
}

#[macro_export]
macro_rules! parser_oncem {
    ( $i: expr, $p: expr, $f: expr, $e: expr, $ef: expr ) => {
        let tempval = $p($i);
        if tempval.is_done() {
            match $f {
                None => {
                    let (iprime, mv) = tempval.unwrap();
                    match mv {
                        Err(e) =>
                            return BitError($ef(e)),
                        Ok(v) => {
                            $f = Some(v);
                            return Continue(iprime)
                        }
                    }
                }
                Some(_) => {
                    return BitError($e);
                }
            }
        }
    }
}

#[macro_export]
macro_rules! try_parser_ {
    ( $i: expr, $p:expr, $c:expr ) => {
        let tempval = $p($i);
        if tempval.is_done() {
            let (iprime, _) = tempval.unwrap();
            $c += 1;
            return Some(iprime);
        }
    }
}

#[macro_export]
macro_rules! force_done {
    ( $i: expr, $err: expr, $inc: expr ) => {
        match $i {
            IResult::Done(a, b) => (a, b),
            IResult::Incomplete(_) =>
                return Err($inc),
            IResult::Error(e) =>
                return Err($err(e))
        }
    }
}

#[macro_export]
macro_rules! force_donem {
    ( $i: expr, $err: expr, $inc: expr, $fe: expr ) => {
        match $i {
            IResult::Done(a, Ok(b)) => (a, b),
            IResult::Done(_, Err(e)) =>
                return Err($fe(e)),
            IResult::Incomplete(_) =>
                return Err($inc),
            IResult::Error(e) =>
                return Err($err(e))
        }
    }
}

#[macro_export]
macro_rules! force_exist {
    ( $i: expr, $e: expr ) => {
        match $i {
            None    => return Err($e),
            Some(v) => v
        }
    }
}

pub fn exactly_once(count: u64, err_few: u32, err_many: u32) -> Result<(),u32>
{
    if count == 0 {
        return Result::Err(err_few);
    }

    if count > 1 {
        return Result::Err(err_many);
    }

    Result::Ok(())
}

pub fn at_most_once(count: u64, err: u32) -> Result<(),u32>
{
    if count > 1 {
        return Result::Err(err);
    }

    Result::Ok(())
}

named!(pub hexbytes<Vec<u8>>,
    map_opt!(hex_digit, convert_hex_string));

named!(pub datetime<DateTime<Utc>>,
    do_parse!(
        d: date >>
        space   >>
        t: time >>
        (DateTime::from_utc(NaiveDateTime::new(d,t),Utc))
    )
);

named!(date<NaiveDate>,
    do_parse!(
        yr: take!(4)                >>
        y: expr_res!(to_number(yr)) >>
        tag!("-")                   >>
        mn: take!(2)                >>
        m: expr_res!(to_number(mn)) >>
        tag!("-")                   >>
        dy: take!(2)                >>
        d: expr_res!(to_number(dy)) >>
        (NaiveDate::from_ymd(y,m,d))
    )
);

named!(time<NaiveTime>,
    do_parse!(
        hr: take!(2)                >>
        h: expr_res!(to_number(hr)) >>
        tag!(":")                   >>
        mn: take!(2)                >>
        m: expr_res!(to_number(mn)) >>
        tag!(":")                   >>
        se: take!(2)                >>
        s: expr_res!(to_number(se)) >>
        (NaiveTime::from_hms(h, m, s))
    )
);

pub const BASE64_CHARS: &'static str =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

named!(pub base64val<Vec<u8>>,
    map_res!(is_a!(BASE64_CHARS), |v| base64::decode(v)));

named!(pub base64_noequals<Vec<u8>>,
    map_res!(is_a!(BASE64_CHARS),tolerant_decode));

named!(pub ip4addr<Ipv4Addr>,
    do_parse!(
        a: decimal_u8 >>
        tag!(".") >>
        b: decimal_u8 >>
        tag!(".") >>
        c: decimal_u8 >>
        tag!(".") >>
        d: decimal_u8 >>
        (Ipv4Addr::new(a,b,c,d))
    )
);

const IP6_CHARS: &'static str =
    "0123456789abcdefABCDEF:";

fn to_ip6(i: &[u8]) -> Option<Ipv6Addr> {
    match str::from_utf8(i) {
        Err(_) => None,
        Ok(v) => Ipv6Addr::from_str(v).ok()
    }
}

named!(pub ip6addr<Ipv6Addr>,
    do_parse!(
        tag!("[")                                           >>
        addr: map_opt!(is_a!(IP6_CHARS.as_bytes()), to_ip6) >>
        tag!("]")                                           >>
        (addr)
    )
);

named!(pub decimal_u8<u8>, map_res!(digit, to_number));
named!(pub decimal_u16<u16>, map_res!(digit, to_number));
named!(pub decimal_u64<u64>, map_res!(digit, to_number));
named!(pub decimal_i32<i32>,
    do_parse!(
        mminus: opt!(tag!("-"))            >>
        value:  map_res!(digit, to_number) >>
        (match mminus {
            None    => value,
            Some(_) => -value
        })
    )
);
named!(pub decimal_i64<i64>,
    do_parse!(
        mminus: opt!(tag!("-"))            >>
        value:  map_res!(digit, to_number) >>
        (match mminus {
            None    => value,
            Some(_) => -value
        })
    )
);

named!(pub pem_public_key<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        tag!("-----BEGIN RSA PUBLIC KEY-----") >>
        newline                                >>
        vs: many1!(base64_line)                >>
        tag!("-----END RSA PUBLIC KEY-----")   >>
        newline                                >>
        (concat_vecs(vs))
    )
);

named!(pub pem_signature<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        alt!(tag!("-----BEGIN ID SIGNATURE-----") |
             tag!("-----BEGIN SIGNATURE-----")) >>
        newline >>
        vs: many1!(base64_line) >>
        alt!(tag!("-----END ID SIGNATURE-----") |
             tag!("-----END SIGNATURE-----")) >>
        newline >>
        (concat_vecs(vs))
    )
);


named!(pub base64_line<&[u8]>,
    do_parse!(
        v: is_a!(BASE64_CHARS) >>
        newline                >>
        (v)
    )
);

named!(pub protocol_version<ProtocolVersion>,
    do_parse!(
        p: protocol_name                                                      >>
        tag!("=")                                                             >>
        v: separated_nonempty_list_complete!(tag!(","),protocol_version_value)>>
        (ProtocolVersion{ protocol: p, versions: v.concat() })
    )
);

named!(protocol_version_value<Vec<u8>>,
    do_parse!(
        v1: decimal_u8                                >>
        mv2: opt!(complete!(do_parse!(tag!("-")       >>
                                      v2: decimal_u8  >>
                                      (v2))))         >>
        (match mv2 {
            None     => vec![v1],
            Some(v2) => (v1..v2+1).collect()
         })
    )
);

named!(protocol_name<Protocol>,
    alt!(
        do_parse!(tag!("Cons")      >> (Protocol::ConsensusDoc))            |
        do_parse!(tag!("Desc")      >> (Protocol::Descriptor))              |
        do_parse!(tag!("DirCache")  >> (Protocol::DirCache))                |
        do_parse!(tag!("HSDir")     >> (Protocol::HiddenServiceDir))        |
        do_parse!(tag!("HSIntro")   >> (Protocol::HiddenServiceIntro))      |
        do_parse!(tag!("HSRend")    >> (Protocol::HiddenServiceRendezvous)) |
        do_parse!(tag!("LinkAuth")  >> (Protocol::LinkAuth))                |
        do_parse!(tag!("Link")      >> (Protocol::Link))                    |
        do_parse!(tag!("Microdesc") >> (Protocol::MicroDescriptor))         |
        do_parse!(tag!("Relay")     >> (Protocol::Relay))
    )
);

named!(pub toraddr4<TorAddress>, map!(ip4addr, |v| TorAddress::IPv4Addr(v)));
named!(pub toraddr6<TorAddress>, map!(ip6addr, |v| TorAddress::IPv6Addr(v)));

named!(pub nickname<String>,
    map_res!(many_m_n!(1,19,alphanumeric1), String::from_utf8));

fn is_alphanumeric_opt(i: u8) -> Option<u8> {
    if is_alphanumeric(i) { Some(i) } else { None }
}

named!(alphanumeric1<u8>,
    map_opt!(be_u8,is_alphanumeric_opt));

pub const NEWLINE_CHAR: &'static str =
    "\n";

named!(pub generic_string<OsString>,
    map!(is_not!(NEWLINE_CHAR), |s| OsString::from_vec(s.to_vec())));

named!(pub accept_rules<Vec<PortInfo>>,
    do_parse!(
        tag!("accept")                                                     >>
        sp                                                                 >>
        vs: separated_nonempty_list_complete!(tag!(","),accept_port_range) >>
        (vs)
    )
);

named!(pub reject_rules<Vec<PortInfo>>,
    do_parse!(
        tag!("reject")                                                     >>
        sp                                                                 >>
        vs: separated_nonempty_list_complete!(tag!(","),reject_port_range) >>
        (vs)
    )
);

named!(accept_port_range<PortInfo>,
    do_parse!(
        p1: decimal_u16                                                   >>
        optpt2: opt!(complete!(do_parse!(tag!("-")>>p:decimal_u16>>(p)))) >>
        (match optpt2 {
            None     => PortInfo::AcceptPort(p1),
            Some(p2) => PortInfo::AcceptRange(p1,p2)
        })
    )
);

named!(reject_port_range<PortInfo>,
    do_parse!(
        p1: decimal_u16                                                   >>
        optpt2: opt!(complete!(do_parse!(tag!("-")>>p:decimal_u16>>(p)))) >>
        (match optpt2 {
            None     => PortInfo::RejectPort(p1),
            Some(p2) => PortInfo::RejectRange(p1,p2)
        })
    )
);


pub fn force_string(i: &[u8]) -> Option<String> {
    match str::from_utf8(i) {
        Err(_) => None,
        Ok(v) =>
            match String::from_str(v) {
                Err(_) => None,
                Ok(res) => Some(res)
            }
    }
}


pub fn concat_vecs(vs: Vec<&[u8]>) -> Result<Vec<u8>,DecodeError> {
    let mut res = Vec::new();

    for slice in vs {
        let mut temp = slice.to_vec();
        res.append(&mut temp);
    }

    base64::decode(&res)
}

fn tolerant_decode(i: &[u8]) -> Result<Vec<u8>,DecodeError> {
    let mut fixed_input = vec![];
    let len_mod4 = i.len() % 4;

    fixed_input.extend_from_slice(i);
    if len_mod4 == 2 {
        fixed_input.extend_from_slice("==".as_bytes());
    }
    if len_mod4 == 3 {
        fixed_input.extend_from_slice("=".as_bytes());
    }

    base64::decode(&fixed_input)
}

fn convert_hex_string(str: &[u8]) -> Option<Vec<u8>>
{
    let target_size = str.len() / 2;
    let mut result = Vec::with_capacity(target_size);

    if (target_size * 2) != str.len() {
        return None
    }

    for i in 0..target_size {
        let index1 = char::from(str[i * 2]);
        let index2 = char::from(str[(i * 2) + 1]);

        match (index1.to_digit(16), index2.to_digit(16)) {
            (Some(left), Some(right)) =>
                result.push(((left as u8) << 4) | (right as u8)),
            (_, _) =>
                return None
        }
    }

    Some(result)
}

pub fn to_number<T>(v: &[u8]) -> Result<T,T::Err>
where
    T: FromStr
{
    match str::from_utf8(v) {
        Err(e) =>
            panic!("Couldn't get number string {:?}",e),
        Ok(s) =>
            FromStr::from_str(s)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn done<T>(result: T) -> IResult<&'static[u8],T> {
        IResult::Done(&b""[..],result)
    }

    #[test]
    fn decimals_work() {
        assert_eq!(decimal_u8(b"0"), done(0));
        assert_eq!(decimal_u8(b"25"), done(25));
        assert_eq!(decimal_u64(b"300"), done(300));
        assert_eq!(decimal_u64(b"9239434934"), done(9239434934));
        assert_eq!(decimal_i32(b"9434934"), done(9434934));
        assert_eq!(decimal_i32(b"-9434934"), done(-9434934));
        assert_eq!(decimal_i32(b"-013"), done(-13));
        assert_eq!(decimal_i64(b"-19239434934"), done(-19239434934));
    }

    #[test]
    fn hexbytes_works() {
        assert_eq!(hexbytes(b"00"), done(vec![0]));
        assert_eq!(hexbytes(b"09"), done(vec![9]));
        assert_eq!(hexbytes(b"0c"), done(vec![12]));
        assert_eq!(hexbytes(b"0C"), done(vec![12]));
        assert_eq!(hexbytes(b"f0"), done(vec![240]));
        assert_eq!(hexbytes(b"F0"), done(vec![240]));
        assert_eq!(hexbytes(b"F2"), done(vec![242]));
        assert_eq!(hexbytes(b"DeaDBEEF"), done(vec![222,173,190,239]));
        assert_eq!(hexbytes(b"0000110000"), done(vec![0,0,17,0,0]));
        assert_eq!(hexbytes(b"00001100000"),
                   IResult::Error(error_code!(ErrorKind::MapOpt)));
        assert_eq!(hexbytes(b"A178748E4F39B9DAC2D373E990388AA32BE6DE6E"),
                   done(vec![0xA1,0x78,0x74,0x8E,0x4F,0x39,0xB9,0xDA,
                             0xC2,0xD3,0x73,0xE9,0x90,0x38,0x8A,0xA3,
                             0x2B,0xE6,0xDE,0x6E]));
    }

    #[test]
    fn date_works() {
        assert_eq!(date(b"2017-06-16"), done(NaiveDate::from_ymd(2017,6,16)));
        assert_eq!(date(b"2017-12-02"), done(NaiveDate::from_ymd(2017,12,2)));
    }

    #[test]
    fn time_works() {
        assert_eq!(time(b"00:00:00"), done(NaiveTime::from_hms(0,0,0)));
        assert_eq!(time(b"03:00:00"), done(NaiveTime::from_hms(3,0,0)));
        assert_eq!(time(b"04:00:00"), done(NaiveTime::from_hms(4,0,0)));
        assert_eq!(time(b"06:00:00"), done(NaiveTime::from_hms(6,0,0)));
        assert_eq!(time(b"18:00:00"), done(NaiveTime::from_hms(18,0,0)));
    }

    #[test]
    fn base64_works() {
        assert_eq!(base64val(b"G0tZRb/ahbK5nFgh0AWUVdy4j0U9Siwf2U8ZcAdJGjc="),
                   done(vec![0x1b,0x4b,0x59,0x45,0xbf,0xda,0x85,0xb2,0xb9,0x9c,
                             0x58,0x21,0xd0,0x05,0x94,0x55,0xdc,0xb8,0x8f,0x45,
                             0x3d,0x4a,0x2c,0x1f,0xd9,0x4f,0x19,0x70,0x07,0x49,
                             0x1a,0x37]));
         assert_eq!(base64val(b"ot0icPHUE9JyVZDhYJT+Kf6mNrN+BLXjcbxbqvnpeBI="),
                   done(vec![0xa2,0xdd,0x22,0x70,0xf1,0xd4,0x13,0xd2,0x72,0x55,
                             0x90,0xe1,0x60,0x94,0xfe,0x29,0xfe,0xa6,0x36,0xb3,
                             0x7e,0x04,0xb5,0xe3,0x71,0xbc,0x5b,0xaa,0xf9,0xe9,
                             0x78,0x12]));
         assert_eq!(
             base64_noequals(b"ot0icPHUE9JyVZDhYJT+Kf6mNrN+BLXjcbxbqvnpeBI="),
             done(vec![0xa2,0xdd,0x22,0x70,0xf1,0xd4,0x13,0xd2,0x72,0x55,
                       0x90,0xe1,0x60,0x94,0xfe,0x29,0xfe,0xa6,0x36,0xb3,
                       0x7e,0x04,0xb5,0xe3,0x71,0xbc,0x5b,0xaa,0xf9,0xe9,
                       0x78,0x12]));
         assert_eq!(base64val(b"Kdm6LYzjnc4MvAp59IwiFLSwdos"),
                   done(vec![41, 217, 186, 45, 140, 227, 157, 206, 12, 188, 10,
                             121, 244, 140, 34, 20, 180, 176, 118, 139]));
    }

    #[test]
    fn ip4_works() {
        assert_eq!(ip4addr(b"0.0.0.0"), done(Ipv4Addr::new(0,0,0,0)));
        assert_eq!(ip4addr(b"255.255.255.255"),
                   done(Ipv4Addr::new(255,255,255,255)));
        assert_eq!(ip4addr(b"193.23.244.244"),
                   done(Ipv4Addr::new(193,23,244,244)));
    }

    #[test]
    fn ip6_works() {
        assert_eq!(ip6addr(b"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]"),
                   done(Ipv6Addr::new(0x2001,0x0db8,0x85a3,0x0000,
                                      0x0000,0x8a2e,0x0370,0x7334)));
        assert_eq!(ip6addr(b"[2001:0db8:85a3:0:0:8a2e:0370:7334]"),
                   done(Ipv6Addr::new(0x2001,0x0db8,0x85a3,0x0000,
                                      0x0000,0x8a2e,0x0370,0x7334)));
        assert_eq!(ip6addr(b"[2001:0db8:85a3::8a2e:0370:7334]"),
                   done(Ipv6Addr::new(0x2001,0x0db8,0x85a3,0x0000,
                                      0x0000,0x8a2e,0x0370,0x7334)));
        assert_eq!(ip6addr(b"[::23]"), done(Ipv6Addr::new(0,0,0,0,0,0,0,0x23)));
    }

    #[test]
    fn signature_test() {
        assert!(base64_line(b"ZwxcsK2sdF7ZYyiJ6cWzFaQ+m5DF4Wl43/UMuJhpiMswi6meKgDPLSWBZoRYNehC\n").is_done());
        assert!(base64_line(b"PiwqxFGBku9icKbIi0Hqd/CCKr0zmGvnSkQU3sbbDYSd0dkzBmaFHtJRjKVitLZ4\n").is_done());
        assert!(base64_line(b"Chz0tJegSQFaaoxLC+XMjY/5L0W8xawVFMGcfsA1LSrHAAqSLBWJyxlFE0IFO1Os\n").is_done());
        assert!(base64_line(b"cA2Jvn+fuXLcl/u6IAr/S1XnjA01+0asb4BZ+NlsS90=\n").is_done());
        assert!(pem_signature(b"-----BEGIN ID SIGNATURE-----\nZwxcsK2sdF7ZYyiJ6cWzFaQ+m5DF4Wl43/UMuJhpiMswi6meKgDPLSWBZoRYNehC\n-----END ID SIGNATURE-----\n").is_done());
        assert!(pem_signature(b"-----BEGIN ID SIGNATURE-----\nZwxcsK2sdF7ZYyiJ6cWzFaQ+m5DF4Wl43/UMuJhpiMswi6meKgDPLSWBZoRYNehC\nWZyFow2HCRYsYxJ7Ycf+PXH4TvX95NBJI6P8dC1lLw7eWHQcIlrHOtiXxy/oeNko\nBOojc6es2s+6wDjSkehLElj5LuIUKnT8+nvIFEQcg6ulN3i8mL/+JRFscyNZyt/w\nmhDGGMdrd9jqPlfdfBZPXnDtkSiCvduVNJo3utvmr029ws1xR/xvShi0v09ahunI\noHCnTeYQx2Xsw5bsbuXIJ880uQCg5RIOhRCBKPvirEiayhsjDQGPkpqHtqDNdLpY\nz9PMkupuNEPjCbYfk+nhZQ==\n-----END ID SIGNATURE-----\n").is_done());
        assert!(pem_signature(b"-----BEGIN SIGNATURE-----\nVxZjrXY5U84TFu46Fx3vPga6DLleMjd5Uay9w9ZNxewm7HmdQZGC7cpwJSqx0qEm\n7ntzStsyUR+C8J8XbSViBdWgsr3jMYPBk8+gZO/QnAzTG2xgl7tdYQ91Jknp+PVy\n44ljLkbhGiyutbn2LCA6s+nSg5A9Pb0n8k3opCSVMQ0WfYltTKARROXyjzo3P9ZL\n-----END SIGNATURE-----\n").is_done());
    }

    #[test]
    fn nickname_works() {
        assert_eq!(nickname(b"tor26"), done("tor26".to_string()));
        assert_eq!(nickname(b"a"), done("a".to_string()));
        assert_eq!(nickname(b"0123456789012345678"),
                   done("0123456789012345678".to_string()));
        assert_eq!(nickname(b""), IResult::Incomplete(Needed::Size(1)));
        // this last test would probably better be an error (FIXME)
        assert_eq!(nickname(b"01234567890123456789"),
                   IResult::Done(&b"9"[..], "0123456789012345678".to_string()));
    }


}
