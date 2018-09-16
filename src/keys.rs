extern crate base16;
extern crate base58;
extern crate byteorder;
extern crate rand;
extern crate ripemd160;
extern crate secp256k1;
extern crate serde;
extern crate sha2;

use std::vec::Vec;

use self::base58::{ToBase58, FromBase58};
use self::byteorder::{LittleEndian, ByteOrder};
use self::ripemd160::{Digest as RipeMD160Digest, Ripemd160};
use self::secp256k1::{Secp256k1, SecretKey, PublicKey};
use self::sha2::{Digest as Sha2Digest, Sha256};

use super::constants;

type Address = String;

pub fn generate_address(pub_key: &PublicKey) -> Address {
    let pub_key_hash = ripemd160::<Ripemd160>(&sha256::<Sha256>(&pub_key.serialize()));
    encode_base58_check(constants::BITCOIN_ADDRESS_VERSION_PREFIX, &pub_key_hash)
}

pub fn encode_base58_check(version_prefix: u8, s: &[u8]) -> String {
    let mut v = Vec::with_capacity(s.len()+1);
    v.push(version_prefix);
    v.extend_from_slice(s);
    let checksum_ref = &sha256::<Sha256>(&sha256::<Sha256>(&v));
    v.extend_from_slice(&checksum_ref[0..4]);
    v.to_base58()
}

pub fn decode_base58_check(s: &String) -> (u8, String, u32) {
    let buf = s.from_base58().unwrap();
    let version_prefix_index = 0;
    let payload_bounds = (1, buf.len()-4);
    let checksum_index = buf.len()-4;

    let version_prefix = buf[version_prefix_index];

    let mut payload = Vec::new();
    payload.extend_from_slice(&buf[payload_bounds.0..payload_bounds.1]);

    let mut checksum = [0u8; 4];
    checksum.clone_from_slice(&buf[checksum_index..]);

    (version_prefix, base16::encode_lower(&payload), LittleEndian::read_u32(&checksum))
}

type WIF = String;

pub fn wif(priv_key: &SecretKey) -> WIF {
    let decoded = base16::decode(priv_key.to_string().as_bytes()).unwrap();
    encode_base58_check(constants::BITCOIN_PRIVATE_KEY_WIF_VERSION_PREFIX, &decoded)
}

type WIFCompressed = String;

pub fn wif_compressed(priv_key: &SecretKey) -> WIFCompressed {
    let decoded = base16::decode(priv_key.to_string().as_bytes()).unwrap();
    let mut wc = Vec::with_capacity(decoded.len()+1);
    wc.extend_from_slice(&decoded);
    wc.push(constants::BITCOIN_WIF_COMPRESSED_SUFFIX);
    encode_base58_check(constants::BITCOIN_PRIVATE_KEY_WIF_VERSION_PREFIX, &wc)
}

fn sha256<D: Sha2Digest + Default>(s: &[u8]) -> [u8; 32] {
    let mut hasher = D::default();
    hasher.digest(&s);
    let mut buf = [0u8; 32];
    &buf.clone_from_slice(hasher.result().as_slice());
    buf
}

fn ripemd160<D: RipeMD160Digest + Default>(s: &[u8]) -> [u8; 20] {
    let mut hasher = D::default();
    hasher.input(&s);
    let mut buf = [0u8; 20];
    &buf.clone_from_slice(hasher.result().as_slice());
    buf
}

#[test]
fn test_address() {
    let secp = Secp256k1::new();
    let sk = base16::decode("038109007313a5807b2eccc082c8c3fbb988a973cacf1a7df9ce725c31b14776").unwrap();
    let sec_key = SecretKey::from_slice(&secp, &sk).expect("32 bytes");
    let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
    let address = generate_address(&pub_key);

    assert_eq!(address, "1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK")
}

#[test]
fn test_base58_check_decode() {
    let wif = "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn".to_string();
    let (version, payload, checksum) = decode_base58_check(&wif);

    assert_eq!(version, 128u8);
    assert_eq!(payload, "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd".to_string());
    assert_eq!(checksum, 4286807748u32);
}

#[test]
fn test_wif() {
    let secp = Secp256k1::new();
    let sk = base16::decode("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd").unwrap();
    let sec_key = SecretKey::from_slice(&secp, &sk).expect("32 bytes");
    let wif = wif(&sec_key);

    assert_eq!(wif, "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn")
}

#[test]
fn test_wif_compressed() {
    let secp = Secp256k1::new();
    let sk = base16::decode("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd").unwrap();
    let sec_key = SecretKey::from_slice(&secp, &sk).expect("32 bytes");
    let wif = wif_compressed(&sec_key);

    assert_eq!(wif, "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ");
}
