use byteorder::{ByteOrder,BE};
use chrono::{DateTime,NaiveDateTime,Utc};

#[derive(Debug)]
pub struct Ed25519Certificate {
    pub cert_type: Ed25519CertType,
    pub expiration_date: DateTime<Utc>,
    pub key: Ed25519PublicKey,
    pub extensions: Vec<EdCertExtension>
}

#[derive(Debug)]
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
        let n_extensions = bytes[39];
        // EXTENSIONS      [N_EXTENSIONS times]
        // SIGNATURE       [64 Bytes]
        if let Some((exts, signature)) = parse_extensions(n_extensions, &bytes[40..]) {

            let pubkey = Ed25519PublicKey{ n: key };
            return Some(Ed25519Certificate{
                cert_type: cert_type,
                expiration_date: expiration_date,
                key: pubkey,
                extensions: exts
            })
        }
        None
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn foo() {
        let mut fd = File::open("test.ed25519").unwrap();
        let mut buffer = Vec::new();
        fd.read_to_end(&mut buffer);
        let res = Ed25519Certificate::decode(&buffer);
        println!("Decoded {:?}", res);
        assert!(false);
    }
}
