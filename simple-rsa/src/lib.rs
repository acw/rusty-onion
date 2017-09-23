extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
extern crate rand;

use num::{BigInt,BigUint,FromPrimitive,Integer,One,Signed,Zero};
use num::bigint::Sign;
use rand::Rng;
use std::ops::Neg;
use std::cmp::Ordering;

const MILLER_RABIN_K: usize = 5;

#[derive(Clone,Debug)]
pub struct RSAKeyPair {
    pub private: RSAPrivateKey,
    pub public:  RSAPublicKey
}

#[derive(Clone,Debug)]
pub struct RSAPublicKey {
    pub key_length: usize,
    pub n: BigUint,
    pub e: BigUint
}

#[derive(Clone,Debug)]
pub struct RSAPrivateKey {
    pub key_length: usize,
    pub n: BigUint,
    pub d: BigUint
}

const ACCEPTABLE_KEY_SIZES: [usize; 5] = [ 512, 1024, 2048, 4096, 8192 ];

pub fn generate_keys<G: Rng>(rng: &mut G, len_bits: usize)
    -> Option<RSAKeyPair>
{
    let one: BigUint = One::one();

    // make sure we get a reasonable key size
    if !ACCEPTABLE_KEY_SIZES.contains(&len_bits) {
        return None;
    }

    let len_bytes = len_bits / 8;
    let (p, q) = generate_pq(rng, len_bytes);
    let n = &p * &q;
    let phi = (p - &one) * (q - &one);
    let e = BigUint::from_u32(65537).unwrap();
    let d = modular_inverse(&e, &phi);

    let public_key  = RSAPublicKey{ key_length: len_bytes, n: n.clone(), e: e};
    let private_key = RSAPrivateKey{key_length: len_bytes, n: n,         d: d};

    Some(RSAKeyPair{ private: private_key, public: public_key })
}

fn generate_pq<G: Rng>(rng: &mut G, len_bytes: usize)
    -> (BigUint, BigUint)
{
    loop {
        let possible_p = gen_random_prime(rng, len_bytes / 2);
        let possible_q = gen_random_prime(rng, len_bytes - (len_bytes / 2));

        match possible_p.cmp(&possible_q) {
            Ordering::Less    => return (possible_q, possible_p),
            Ordering::Equal   => continue,
            Ordering::Greater => return (possible_p, possible_q)
        }
    }
}

// Generate a random number, with the given length in bytes.
fn gen_random_prime<G: Rng>(rng: &mut G, len: usize) -> BigUint {
    // turn it into a number
    let mut n = random_biguint(rng, len);
    let one = One::one();
    let two = BigUint::from_u8(2).unwrap();
    let two16plus1 = BigUint::from_u32(65537).unwrap();

    n = n | &one;
    n = n | (one.clone() << (len - 1));

    loop {
        if n.is_even() {
            n = n.clone() + &one;
        }
        else if n.mod_floor(&two16plus1) == one {
            n = n.clone() + &two;
        }
        else if is_probably_prime(rng, &n, len) {
            return n;
        } else {
            n = n.clone() + &two;
        }
    }
}

fn is_probably_prime<G: Rng>(rng: &mut G, n: &BigUint, size: usize) -> bool {
    // a quick check against the smallest 200 primes
    for i in 0 .. SMALL_PRIMES.len() {
        if (n.clone() % SMALL_PRIMES[i]).is_zero() {
            return false;
        }
    }

    // a less quick check using Miller-Rabin
    let one: BigUint = One::one();

    // write n - 1 as (2^r)*d, where d is odd, by factoring powers of 2 from
    // n - 1.
    let mut r: BigUint = Zero::zero();
    let mut d: BigUint = n.clone() - &one;
    while d.is_even() {
        r = r + &one;
        d = d >> 1;
    }

    // the witness loop (comments via Wikipedia)
    let n_minus_1 = n.clone() - &one;
    let two = BigUint::from_u8(2).unwrap();
    // WitnessLoop: repeat k times:
    'WitnessLoop: for _ in 0 .. MILLER_RABIN_K {
        // pick a random integer a in the range [2, n - 1]
        let a = choose_random(rng, size, &two, &n_minus_1);
        // x <- a^d mod n
        let mut x = modular_exponentiation(&a, &d, &n);

        // if x = 1 or x = n - 1 then
        //   continue WitnessLoop
        if (&x == &one) || (&x == &n_minus_1) {
            continue 'WitnessLoop;
        }
        // repeat r - 1 times:
        let mut i = r.clone();
        while !i.is_zero() {
            // x <- x^2 mod n
            x = modular_exponentiation(&x, &two, &n);
            // if x = 1 then
            //   return composite
            if &x == &one {
                return false;
            }
            // if x = n - 1 then
            //   continue WitnessLoop
            if &x == &n_minus_1 {
                continue 'WitnessLoop;
            }
            i = i - &one;
        }
        // return composite
        return false;
    }

    true
}

fn choose_random<G: Rng>(rng: &mut G, len: usize, low: &BigUint, high: &BigUint)
    -> BigUint
{
    loop {
        let possible = random_biguint(rng, len);
        if (&possible >= low) && (&possible <= high) {
            return possible;
        }
    }
}

fn random_biguint<G: Rng>(rng: &mut G, len: usize) -> BigUint {
    let mut buffer = Vec::with_capacity(len);
    buffer.resize(len, 0);
    rng.fill_bytes(buffer.as_mut_slice());
    BigUint::from_bytes_le(&buffer)
}

static SMALL_PRIMES: [u32; 200] = [
       2,     3,     5,     7,    11,    13,    17,    19,    23,    29,
      31,    37,    41,    43,    47,    53,    59,    61,    67,    71,
      73,    79,    83,    89,    97,   101,   103,   107,   109,   113,
     127,   131,   137,   139,   149,   151,   157,   163,   167,   173,
     179,   181,   191,   193,   197,   199,   211,   223,   227,   229,
     233,   239,   241,   251,   257,   263,   269,   271,   277,   281,
     283,   293,   307,   311,   313,   317,   331,   337,   347,   349,
     353,   359,   367,   373,   379,   383,   389,   397,   401,   409,
     419,   421,   431,   433,   439,   443,   449,   457,   461,   463,
     467,   479,   487,   491,   499,   503,   509,   521,   523,   541,
     547,   557,   563,   569,   571,   577,   587,   593,   599,   601,
     607,   613,   617,   619,   631,   641,   643,   647,   653,   659,
     661,   673,   677,   683,   691,   701,   709,   719,   727,   733,
     739,   743,   751,   757,   761,   769,   773,   787,   797,   809,
     811,   821,   823,   827,   829,   839,   853,   857,   859,   863,
     877,   881,   883,   887,   907,   911,   919,   929,   937,   941,
     947,   953,   967,   971,   977,   983,   991,   997,  1009,  1013,
    1019,  1021,  1031,  1033,  1039,  1049,  1051,  1061,  1063,  1069,
    1087,  1091,  1093,  1097,  1103,  1109,  1117,  1123,  1129,  1151,
    1153,  1163,  1171,  1181,  1187,  1193,  1201,  1213,  1217,  1223
];

pub fn pkcs1_sign(private: &RSAPrivateKey, ident: &[u8], hash: &[u8]) -> Vec<u8> {
    let em = pkcs1_pad(ident, hash, private.key_length);
    let m  = o2isp(&em);
    let s  = sp1(&private.n, &private.d, &m);
    let sig = i2osp(&s, private.key_length);
    sig
}

pub fn pkcs1_verify(public: &RSAPublicKey, ident: &[u8], hash: &[u8], sig: &Vec<u8>)
    -> bool
{
    let s   = o2isp(sig);
    let m   = vp1(&public.n, &public.e, &s);
    let em  = i2osp(&m, public.key_length);
    let em_ = pkcs1_pad(ident, hash, public.key_length);
    (em == em_)
}

// encoding PKCS1 stuff
fn pkcs1_pad(ident: &[u8], hash: &[u8], keylen: usize) -> Vec<u8> {
    let mut idhash = Vec::new();
    idhash.extend_from_slice(ident);
    idhash.extend_from_slice(hash);
    let tlen = idhash.len();
    assert!(keylen > (tlen + 3));
    let mut padding = Vec::new();
    padding.resize(keylen - tlen - 3, 0xFF);
    let mut result = vec![0x00, 0x01];
    result.append(&mut padding);
    result.push(0x00);
    result.append(&mut idhash);
    result
}

// convert an integer into series of bytes
fn i2osp(x: &BigUint, len: usize) -> Vec<u8> {
    let mut base = x.to_bytes_be();

    // If the length is too long, chop off the first few bytes.
    while base.len() > len {
        base.remove(0);
    }

    // If the length is too short, pad the front.
    while base.len() < len {
        base.insert(0,0);
    }

    base
}

// convert a series of bytes into a number
fn o2isp(x: &Vec<u8>) -> BigUint {
    BigUint::from_bytes_be(&x)
}

// the RSA encryption function
fn ep(n: &BigUint, e: &BigUint, m: &BigUint) -> BigUint {
    modular_exponentiation(m, e, n)
}

// the RSA decryption function
fn dp(n: &BigUint, d: &BigUint, c: &BigUint) -> BigUint {
    modular_exponentiation(c, d, n)
}

// the RSA signature generation function
fn sp1(n: &BigUint, d: &BigUint, m: &BigUint) -> BigUint {
    modular_exponentiation(m, d, n)
}

// the RSA signature verification function
fn vp1(n: &BigUint, e: &BigUint, s: &BigUint) -> BigUint {
    modular_exponentiation(s, e, n)
}

// fast modular exponentiation
fn modular_exponentiation(x: &BigUint, y: &BigUint, m: &BigUint) -> BigUint {
    let mut b      = x.clone() % m;
    let mut e      = y.clone();
    let mut result = One::one();

    loop {
        if e.is_zero() {
            return result;
        }

        if e.is_odd() {
            result = (result * &b) % m;
        }

        b = (b.clone() * &b) % m;
        e = e.clone() >> 1;
    }
}

// fast modular inverse
fn modular_inverse(e: &BigUint, phi: &BigUint) -> BigUint {
    let (_, mut x, _) = extended_euclidean(&e, &phi);
    let int_phi = BigInt::from_biguint(Sign::Plus, phi.clone());
    while x.is_negative() {
        x = x + &int_phi;
    }
    x.to_biguint().unwrap()
}

fn extended_euclidean(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    let pos_int_a = BigInt::from_biguint(Sign::Plus, a.clone());
    let pos_int_b = BigInt::from_biguint(Sign::Plus, b.clone());
    let (d, x, y) = egcd(pos_int_a, pos_int_b);

    if d.is_negative() {
        (d.neg(), x.neg(), y.neg())
    } else {
        (d, x, y)
    }
}

fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    let mut s: BigInt = Zero::zero();
    let mut old_s     = One::one();
    let mut t: BigInt = One::one();
    let mut old_t     = Zero::zero();
    let mut r         = b.clone();
    let mut old_r     = a.clone();

    while !r.is_zero() {
        let quotient = old_r.clone() / r.clone();

        let prov_r = r.clone();
        let prov_s = s.clone();
        let prov_t = t.clone();

        r = old_r - (r * &quotient);
        s = old_s - (s * &quotient);
        t = old_t - (t * &quotient);

        old_r = prov_r;
        old_s = prov_s;
        old_t = prov_t;
    }

    (old_r, old_s, old_t)
}

#[cfg(test)]
mod tests {
    use num::cast::FromPrimitive;
    use num::{Integer,pow};
    use quickcheck::{Arbitrary,Gen};
    use std::ops::Shl;
    use super::*;

    #[derive(Clone,Debug)]
    struct WrappedInt {
        n: BigUint
    }

    impl Arbitrary for WrappedInt {
        fn arbitrary<G: Gen>(g: &mut G) -> WrappedInt {
            let len = g.gen::<u16>() % 512;
            let mut storage = Vec::new();

            for _ in 0..len {
                storage.push(g.gen::<u32>());
            }

            let uint = BigUint::new(storage);

            if uint.is_zero() {
                WrappedInt{ n: One::one() }
            } else {
                WrappedInt{ n: uint }
            }
        }
    }

    quickcheck! {
        fn serialization_roundtrips(n: WrappedInt) -> bool {
            let one = BigUint::from_u8(1).unwrap();
            let one_shift = one.shl(4096);
            let nlimited = n.n.mod_floor(&one_shift);
            let bstr = i2osp(&nlimited, 4096 / 8);
            let nback = o2isp(&bstr);
            nback == nlimited
        }
    }

    quickcheck! {
        fn deserialization_roundtrips(v: Vec<u8>, l: usize) -> bool {
            let lprime = if v.len() < l { v.len() } else { l };
            let mut vclone = v.clone();
            vclone.truncate(lprime);
            let int = o2isp(&vclone);
            let vprime = i2osp(&int, lprime);
            vclone == vprime
        }
    }

    #[derive(Clone,Debug)]
    struct SmallerInt {
        n: BigUint
    }

    impl Arbitrary for SmallerInt {
        fn arbitrary<G: Gen>(g: &mut G) -> SmallerInt {
            loop {
                let v = g.gen::<u32>();
                if v > 0 {
                    let uint = BigUint::from_u32(v).unwrap();
                    return SmallerInt{ n: uint }
                }
            }
        }
    }

    quickcheck! {
        fn modexp_works(b: SmallerInt, e: usize, m: SmallerInt) -> bool {
            let euint = BigUint::from(e);
            let mine = modular_exponentiation(&b.n, &euint, &m.n);
            let reg  = pow(b.n, e) % m.n;
            mine == reg
        }
    }

    #[derive(Clone,Debug)]
    struct LargePrime {
        n: BigUint
    }

    impl Arbitrary for LargePrime {
        fn arbitrary<G: Gen>(g: &mut G) -> LargePrime {
            let uint = gen_random_prime(g, 8);
            LargePrime{ n: uint }
        }
    }

    quickcheck! {
        fn modinv_works(p: LargePrime, q: LargePrime) -> bool {
            let one = One::one();
            let e = BigUint::from_u32(65537).unwrap();
            let phi = (p.n - &one) * (q.n - &one);
            let d = modular_inverse(&e, &phi);
            (e * d) % phi == one
        }
    }

    #[derive(Clone,Debug)]
    struct SmallKeyPair {
        kp: RSAKeyPair
    }

    impl Arbitrary for SmallKeyPair {
        fn arbitrary<G: Gen>(g: &mut G) -> SmallKeyPair {
            let kp = generate_keys(g, 512).unwrap();
            SmallKeyPair{ kp: kp }
        }
    }

    #[derive(Clone,Debug)]
    struct Uint512Bit {
        n: BigUint
    }

    impl Arbitrary for Uint512Bit {
        fn arbitrary<G: Gen>(g: &mut G) -> Uint512Bit {
            let mut m_bytes = Vec::new();
            for _ in 0..16 {
                m_bytes.push(g.gen::<u32>());
            }
            let m = BigUint::new(m_bytes);
            Uint512Bit{ n: m }
        }
    }

    quickcheck! {
        fn rsa_ep_dp_inversion(skp: SmallKeyPair, v: Uint512Bit) -> bool {
            let m = v.n % &skp.kp.public.n;
            let ciphertext = ep(&skp.kp.public.n, &skp.kp.public.e, &m);
            let mprime = dp(&skp.kp.private.n, &skp.kp.private.d, &ciphertext);
            mprime == m
        }
    }

    quickcheck! {
        fn rsa_sp_vp_inversion(skp: SmallKeyPair, v: Uint512Bit) -> bool {
            let m = v.n % &skp.kp.public.n;
            let sig = sp1(&skp.kp.private.n, &skp.kp.private.d, &m);
            let mprime = vp1(&skp.kp.public.n, &skp.kp.public.e, &sig);
            mprime == m
        }
    }

    #[derive(Clone,Debug)]
    struct Message {
        m: Vec<u8>
    }

    impl Arbitrary for Message {
        fn arbitrary<G: Gen>(g: &mut G) -> Message {
            let len = 1 + (g.gen::<u8>() % 32);
            let mut storage = Vec::new();
            for _ in 0..len {
                storage.push(g.gen::<u8>());
            }
            Message{ m: storage }
        }
    }

    quickcheck! {
        fn rsa_sign_verifies(skp: SmallKeyPair, m: Message) -> bool {
            let sig = pkcs1_sign(&skp.kp.private, &[], &m.m);
            pkcs1_verify(&skp.kp.public, &[], &m.m, &sig)
        }
    }
}
