use types::*;
use types::AuthInfoErr::*;
use base64::DecodeError;
use chrono::{DateTime,Utc};
use nom::*;
//use ring::signature::{RSA_PKCS1_NOSIG_2048_8192_SHA1,verify};
use std::net::Ipv4Addr;
use parsing_utils::*;
use parsing_utils::BitParseResult::*;
use untrusted::Input;

#[derive(Debug,Default)]
struct AuthorityParsingState {
    dir_address: Option<(Ipv4Addr,u16)>,
    fingerprint: Option<Vec<u8>>,
    published: Option<DateTime<Utc>>,
    expires: Option<DateTime<Utc>>,
    identity_key: Option<Vec<u8>>,
    signing_key: Option<Vec<u8>>,
    crosscert: Option<Vec<u8>>,
}

pub fn parse_authority_keys(i: &[u8]) -> Result<AuthorityKeys,AuthInfoErr> {
    let (mut cur_buffer, _) =
        force_done!(certificate_version(&i), ParserError, IncompleteFile);
    let mut state = AuthorityParsingState::default();

    loop {
        match auth_cert_bit(&mut cur_buffer, &mut state) {
            Continue(newbuffer) => cur_buffer = newbuffer,
            BitError(e)         => return Err(e),
            NoBits              => break
        }
    }

    let (finalbuf, _) =
        force_done!(certification(&cur_buffer), ParserError, IncompleteFile);
    let (ending, certification_sig) =
        force_donem!(pem_signature(&finalbuf), ParserError, IncompleteFile, Base64Error);

    // a bunch of validation work:
    if ending.len() > 0 {
        return Err(DataLeftOver);
    }
    let fingerprint = force_exist!(state.fingerprint, TooFewFingerprints);
    let published = force_exist!(state.published, TooFewPublishedFields);
    let expires = force_exist!(state.expires, TooFewExpirationFields);
    let ident = force_exist!(state.identity_key, TooFewIdentityKeys);
    let signing = force_exist!(state.signing_key, TooFewSigningKeys);
    let crosscert = force_exist!(state.crosscert, TooFewCrossCertifications);


    let signing_key = Input::from(&signing);
    let cross_sig = Input::from(&crosscert[..]);
    let cross_data = Input::from(&ident[..]);
    let cross_check = unimplemented!("");
//    let cross_check = verify(&RSA_PKCS1_NOSIG_2048_8192_SHA1, signing_key,
//                             cross_data, cross_sig);
//    if cross_check.is_err() {
//        return Err(CrossCertCheckFailed);
//    }

//    let hashlen = i.len() - finalbuf.len();
//    let ident_key = Input::from(&ident);
//    let sig = Input::from(&certification_sig);
//    let body = Input::from(&i[0..hashlen]);
//    let result = unimplemented!(); // verify(&RSA_PKCS1_NOSIG_2048_8192_SHA1, ident_key, body, sig);
//    if result.is_err() {
//        return Err(SignatureFailed);
//    }

    Ok(AuthorityKeys {
        dir_address:  state.dir_address,
        fingerprint:  fingerprint,
        published:    published,
        expires:      expires,
        identity_key: ident.clone(),
        signing_key:  signing.clone()
    })
}

fn auth_cert_bit<'a>(i: &'a[u8],
                     st: &mut AuthorityParsingState)
    -> BitParseResult<'a,AuthInfoErr>
{
    parser_once!(i, dir_address,  st.dir_address,   TooManyAddresses);
    parser_once!(i, fingerprint,  st.fingerprint,   TooManyFingerprints);
    parser_once!(i, published,    st.published,     TooManyPublishedFields);
    parser_once!(i, expires,      st.expires,       TooManyExpirationFields);
    parser_oncem!(i, identity_key, st.identity_key, TooManyIdentityKeys, Base64Error);
    parser_oncem!(i, signing_key,  st.signing_key,  TooManySigningKeys, Base64Error);
    parser_oncem!(i, cross_cert,   st.crosscert,    TooManyCrossCertifications, Base64Error);
    NoBits
}

named!(certificate_version<()>,
    do_parse!(
        tag!("dir-key-certificate-version") >>
        sp                                  >>
        tag!("3")                           >>
        newline                             >>
        (())
    )
);

named!(dir_address<(Ipv4Addr,u16)>,
    do_parse!(
        tag!("dir-address") >>
        sp                  >>
        a: ip4addr          >>
        tag!(":")           >>
        p: decimal_u16      >>
        newline             >>
        ((a, p))
    )
);

named!(fingerprint<Vec<u8>>,
    do_parse!(
        tag!("fingerprint") >>
        sp >>
        v: hexbytes >>
        newline >>
        (v)
    )
);

named!(published<DateTime<Utc>>,
    do_parse!(
        tag!("dir-key-published") >>
        sp >>
        v: datetime >>
        newline >>
        (v)
    )
);

named!(expires<DateTime<Utc>>,
    do_parse!(
        tag!("dir-key-expires") >>
        sp >>
        v: datetime >>
        newline >>
        (v)
    )
);

named!(identity_key<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        tag!("dir-identity-key") >>
        newline >>
        v: pem_public_key >>
        (v)
    )
);

named!(signing_key<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        tag!("dir-signing-key") >>
        newline >>
        v: pem_public_key >>
        (v)
    )
);

named!(cross_cert<Result<Vec<u8>,DecodeError>>,
    do_parse!(
        tag!("dir-key-crosscert") >>
        newline                   >>
        v: pem_signature          >>
        (v)
    )
);

named!(certification<()>,
    do_parse!(
        tag!("dir-key-certification") >>
        newline                       >>
        (())
    )
);


