extern crate bitcoin;
extern crate rand;
extern crate secp256k1;

use rand::{Rng, thread_rng};
use secp256k1::{Secp256k1, SecretKey, PublicKey};

use bitcoin::keys::{generate_address, decode_base58_check, wif, wif_compressed};

fn main() {
    let secp = Secp256k1::new();

    let mut rng = thread_rng();
    let random_bytes = random_32_bytes(&mut rng);

    let sec_key = SecretKey::from_slice(&secp, &random_bytes).expect("32 bytes");
    let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
    let address = generate_address(&pub_key);
    let (version, payload, checksum) = decode_base58_check(&address);

    println!("secret key: {}", &sec_key);
    println!("public key: {}", &pub_key);
    println!("address: {}", &address);
    println!("base58 decoded - version: {0}, payload: {1:?}, checksum: {2:?}", version, &payload, &checksum);

    let wif_priv_key = wif(&sec_key);
    println!("wif: {}", wif_priv_key);

    let wif_compressed_priv_key = wif_compressed(&sec_key);
    println!("wifc: {}", wif_compressed_priv_key);
}

fn random_32_bytes<R: Rng>(rng: &mut R) -> [u8; 32] {
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    buf
}
