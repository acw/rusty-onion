use base64::DecodeError;
use chrono::{DateTime,Utc};
use nom::ErrorKind;
use std::net::{Ipv4Addr,Ipv6Addr};

pub struct Authority {
    pub nickname: String,
    pub address: Ipv4Addr,
    pub ip6_address: Option<(Ipv6Addr,u16)>,
    pub onion_port: u16,
    pub dir_port: u16,
    pub v3_ident: Vec<u8>,
    pub keys: AuthorityKeys
}

pub struct AuthorityKeys {
    pub dir_address: Option<(Ipv4Addr,u16)>,
    pub fingerprint: Vec<u8>,
    pub published: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub identity_key: Vec<u8>,
    pub signing_key: Vec<u8>,
}

#[derive(Debug)]
pub enum AuthInfoErr {
    DataLeftOver,
    IncompleteFile,
    CrossCertCheckFailed,
    SignatureFailed,
    TooFewFingerprints,
    TooFewIdentityKeys,
    TooFewPublishedFields,
    TooFewExpirationFields,
    TooFewSigningKeys,
    TooFewCrossCertifications,
    TooManyAddresses,
    TooManyFingerprints,
    TooManyPublishedFields,
    TooManyExpirationFields,
    TooManyIdentityKeys,
    TooManySigningKeys,
    TooManyCrossCertifications,
    Base64Error(DecodeError),
    ParserError(ErrorKind),
}

