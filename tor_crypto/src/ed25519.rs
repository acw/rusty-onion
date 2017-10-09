use byteorder::{ByteOrder,BE};
use chrono::{DateTime,NaiveDateTime,Utc};
use ring::signature::{ED25519, verify};
use untrusted::Input;

#[derive(Debug)]
pub struct Ed25519Certificate {
    pub cert_type: Ed25519CertType,
    expiration_date: DateTime<Utc>,
    pub data: CertKeyType,
    extensions: Vec<EdCertExtension>
}

#[derive(Debug)]
pub enum CertKeyType {
    Ed25519(Ed25519PublicKey),
    SHA256RSAHash([u8; 32]),
    SHA256X509Hash([u8; 32])
}

#[derive(Debug,PartialEq)]
pub enum Ed25519CertType {
    SigningKeyWithIdentity,
    TLSLinkCert,
    SignedAuthenticationKey,
    OnionServiceShortTerm,
    OnionServiceIntroPoint,
    NTorOnionKeyCrossCert,
    OnionServiceNTorExtra
}

impl Ed25519CertType {
    pub fn decode(v: u8) -> Option<Ed25519CertType> {
        match v {
            0x04 => Some(Ed25519CertType::SigningKeyWithIdentity),
            0x05 => Some(Ed25519CertType::TLSLinkCert),
            0x06 => Some(Ed25519CertType::SignedAuthenticationKey),
            0x08 => Some(Ed25519CertType::OnionServiceShortTerm),
            0x09 => Some(Ed25519CertType::OnionServiceIntroPoint),
            0x0A => Some(Ed25519CertType::NTorOnionKeyCrossCert),
            0x0B => Some(Ed25519CertType::OnionServiceNTorExtra),
            _    => None
        }
    }

    pub fn encode(self) -> u8 {
        match self {
            Ed25519CertType::SigningKeyWithIdentity   => 0x04,
            Ed25519CertType::TLSLinkCert              => 0x05,
            Ed25519CertType::SignedAuthenticationKey  => 0x06,
            Ed25519CertType::OnionServiceShortTerm    => 0x08,
            Ed25519CertType::OnionServiceIntroPoint   => 0x09,
            Ed25519CertType::NTorOnionKeyCrossCert    => 0x0A,
            Ed25519CertType::OnionServiceNTorExtra    => 0x0B
        }
    }
}

#[derive(Debug)]
pub struct Ed25519PublicKey {
    pub n: [u8; 32]
}

impl Ed25519Certificate {
    pub fn decode(bytes: &[u8]) -> Option<Ed25519Certificate> {
        // According to the Tor spec, this should have the format:
        // VERSION         [1 Byte]
        let version = bytes[0];
        if version != 0x01 {
            return None
        }
        // CERT_TYPE       [1 Byte]
        let cert_type = match Ed25519CertType::decode(bytes[1]) {
                            Some(v) => v,
                            None    => return None
                        };
        // EXPIRATION_DATE [4 Bytes]
        //   Given as the number of hours after the epoch
        let exp_date_hae = BE::read_u32(&bytes[2..6]) as i64;
        let ts = exp_date_hae * 60 * 60; // hours -> seconds
        let ndt = NaiveDateTime::from_timestamp(ts, 0);
        let expiration_date = DateTime::<Utc>::from_utc(ndt, Utc);
        // CERT_KEY_TYPE   [1 byte]
        let cert_key_type = bytes[6];
        // CERTIFIED_KEY   [32 Bytes]
        let mut key: [u8; 32] = [0; 32];
        key.clone_from_slice(&bytes[7..39]);
        // N_EXTENSIONS    [1 byte]
        let n_exts = bytes[39];
        // EXTENSIONS      [N_EXTENSIONS times]
        // SIGNATURE       [64 Bytes]
        if let Some((exts, sig)) = parse_extensions(n_exts, &bytes[40..]) {
            let mandatory = cert_type==Ed25519CertType::SigningKeyWithIdentity;
            if !check_ext_sig(mandatory, &exts, &bytes,  sig) {
                return None;
            }
            let thing = match cert_key_type {
                // A.4. List of certified key types
                //
                // [01] ed25519 key
                0x01 => CertKeyType::Ed25519(Ed25519PublicKey{ n: key }),
                // [02] SHA256 hash of an RSA key
                0x02 => CertKeyType::SHA256RSAHash(key),
                // [03] SHA256 hash of an X.509 certificate
                0x03 => CertKeyType::SHA256X509Hash(key),
                //
                _    => return None

            };
            let pubkey = Ed25519PublicKey{ n: key };
            return Some(Ed25519Certificate{
                cert_type: cert_type,
                expiration_date: expiration_date,
                data: thing,
                extensions: exts
            })
        }
        None
    }

    pub fn subkey_matches(&self, other: &[u8]) -> bool {
        for ext in self.extensions.iter() {
            match ext {
                &EdCertExtension::SigningKey(ref skey) => {
                    return skey.n == other;
                }
            }
        }
        false
    }
}

#[derive(Debug)]
pub enum EdCertExtension {
    SigningKey(Ed25519PublicKey)
}

fn parse_extensions(num: u8, inbuf: &[u8])
    -> Option<(Vec<EdCertExtension>, &[u8])>
{
    let mut count  = num;
    let mut exts   = Vec::new();
    let mut buffer = inbuf;

    while count > 0 {
        let extlen = BE::read_u16(&buffer[0..2]);
        let exttype = buffer[2];
        let extflags = buffer[3];

        match exttype {
            0x04 => {
                // 2.2.1. Signed-with-ed25519-key extension [type 04]
                // In several places, it's desirable to bundle the key signing a
                // certificate along with the certificate.  We do so with this
                // extension.
                //
                //         ExtLength = 32
                if extlen != 32 {
                    return None;
                }
                if buffer.len() < 36 {
                    return None;
                }
                //         ExtData =
                //            An ed25519 key    [32 bytes]
                //
                // When this extension is present, it MUST match the key used to
                // sign the certificate.
                //
                let mut n = [0; 32];
                n.clone_from_slice(&buffer[4..36]);
                let pubkey = Ed25519PublicKey { n: n };
                exts.push(EdCertExtension::SigningKey(pubkey));
                buffer = &buffer[36..];
            }
            _ => {
                if extflags > 0 {
                    return None // AFFECTS_VALIDATION is set
                }
                if buffer.len() < (4 + extlen as usize) {
                    // "it is an error for an extension to be truncated"
                    return None
                }
                buffer = &buffer[4+(extlen as usize) .. ];
            }
        }

        count -= 1;
    }

    Some((exts, buffer))
}

fn check_ext_sig(mandatory: bool,
                 exts: &Vec<EdCertExtension>,
                 bytes: &[u8],
                 sig: &[u8])
    -> bool
{
    for ext in exts.iter() {
        match ext {
            &EdCertExtension::SigningKey(ref pubkey25519) => {
                let pubkey = Input::from(&pubkey25519.n);
                let msg = Input::from(&bytes[0 .. (bytes.len() - 64)]);
                let signature = Input::from(sig);
                let check = verify(&ED25519, pubkey, msg, signature);
                return check.is_ok()
            }
        }
    }

    // if we get here and we haven't returned, then there wasn't a
    // signing key. if one was mandatory, then we should return
    // false, as this is a problem. if it wasn't mandatory, then
    // we're all good
    return !mandatory;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    fn test_ed25519_cert_file(name: &str) {
        let mut fd = File::open(name).unwrap();
        let mut buffer = Vec::new();
        fd.read_to_end(&mut buffer);
        let res = Ed25519Certificate::decode(&buffer);
        assert!(res.is_some());
    }

    #[test]
    fn foo() {
        test_ed25519_cert_file("test/test1.ed25519");
        test_ed25519_cert_file("test/test2.ed25519");
    }
}
