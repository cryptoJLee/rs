// use hkdf::Hkdf;
use rand::thread_rng;
// use secp256k1::{util::FULL_PUBLIC_KEY_SIZE, Error as SecpError, PublicKey, SecretKey};
// use sha2::Sha256;

use crate::consts::EMPTY_BYTES;
use crate::types::AesKey;

// #[cfg(feature = "pure")]
// pub use crate::pure_aes::{aes_decrypt, aes_encrypt};

// #[cfg(feature = "openssl")]
// pub use crate::openssl_aes::{aes_decrypt, aes_encrypt};

// /// Generate a `(SecretKey, PublicKey)` pair
// pub fn generate_keypair() -> (SecretKey, PublicKey) {
//     let sk = SecretKey::random(&mut thread_rng());
//     (sk.clone(), PublicKey::from_secret_key(&sk))
// }

// /// Calculate a shared AES key of our secret key and peer's public key by hkdf
// pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<AesKey, SecpError> {
//     let mut shared_point = peer_pk.clone();
//     shared_point.tweak_mul_assign(&sk)?;

//     let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
//     master.extend(PublicKey::from_secret_key(&sk).serialize().iter());
//     master.extend(shared_point.serialize().iter());

//     hkdf_sha256(master.as_slice())
// }

// /// Calculate a shared AES key of our public key and peer's secret key by hkdf
// pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<AesKey, SecpError> {
//     let mut shared_point = pk.clone();
//     shared_point.tweak_mul_assign(&peer_sk)?;

//     let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
//     master.extend(pk.serialize().iter());
//     master.extend(shared_point.serialize().iter());

//     hkdf_sha256(master.as_slice())
// }

// // private below
// fn hkdf_sha256(master: &[u8]) -> Result<AesKey, SecpError> {
//     let h = Hkdf::<Sha256>::new(None, master);
//     let mut out = [0u8; 32];
//     h.expand(&EMPTY_BYTES, &mut out)
//         .map_err(|_| SecpError::InvalidInputLength)?;
//     Ok(out)
// }

