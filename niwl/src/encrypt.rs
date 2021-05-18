use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use fuzzytags::Tag;
use rand::rngs::OsRng;
use secretbox::CipherType::Salsa20;
use secretbox::SecretBox;
use serde::{Deserialize, Serialize};
use std::ops::Mul;

/// TaggedCiphertext is a wrapper around a Tag and an encrypted payload (in addition to a
/// nonce value).
#[derive(Serialize, Deserialize, Clone)]
pub struct TaggedCiphertext {
    pub tag: Tag<24>,
    nonce: RistrettoPoint,
    ciphertext: Vec<u8>,
}

/// A Private Key used when encrypting to a niwl client
#[derive(Serialize, Deserialize)]
pub struct PrivateKey(Scalar);

/// A Public Key derived from a niwl PrivateKey
#[derive(Serialize, Deserialize)]
pub struct PublicKey(RistrettoPoint);

impl PublicKey {
    /// Encrypt to Tag provides uni-directional encrypted
    pub fn encrypt(&self, tag: &Tag<24>, message: &String) -> TaggedCiphertext {
        // Generate a random point. We will use the public part as a nonce
        // And the private part to generate a key.
        let mut rng = OsRng::default();
        let r = Scalar::random(&mut rng);
        let z = RISTRETTO_BASEPOINT_POINT.mul(r);

        // Compile our (public) nonce...we derive a new random nonce by hashing
        // the public z parameter with the tag.
        let mut nonce_hash = sha3::Sha3_256::new();
        nonce_hash.update(z.compress().as_bytes());
        nonce_hash.update(tag.compress());
        let mut nonce = [0u8; 24];
        nonce[..].copy_from_slice(&nonce_hash.finalize().as_slice()[0..24]);

        // Calculate the key by multiplying part of the tagging key by our private 'r'
        let mut hash = sha3::Sha3_256::new();
        hash.update(self.0.mul(r).compress().as_bytes());
        hash.update(tag.compress());
        let key = hash.finalize().to_vec();
        let secret_box = SecretBox::new(key, Salsa20).unwrap();

        // TODO: Fixed Size Packets
        let ciphertext = secret_box.seal(message.as_bytes(), nonce);
        TaggedCiphertext {
            tag: tag.clone(),
            nonce: z,
            ciphertext,
        }
    }
}

impl PrivateKey {
    pub fn generate() -> PrivateKey {
        let mut rng = OsRng::default();
        let r = Scalar::random(&mut rng);
        PrivateKey { 0: r }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            0: RISTRETTO_BASEPOINT_POINT.mul(self.0),
        }
    }

    /// Decrypt a tagged ciphertext
    pub fn decrypt(&self, ciphertext: &TaggedCiphertext) -> Option<String> {
        // Derive the public nonce...
        let mut nonce_hash = sha3::Sha3_256::new();
        nonce_hash.update(ciphertext.nonce.compress().as_bytes());
        nonce_hash.update(ciphertext.tag.compress());
        let mut nonce = [0u8; 24];
        nonce[..].copy_from_slice(&nonce_hash.finalize().as_slice()[0..24]);

        // Calculate the key by multiplying the public point with our private 'x'
        let mut hash = sha3::Sha3_256::new();
        hash.update(ciphertext.nonce.mul(self.0).compress().as_bytes());
        hash.update(ciphertext.tag.compress());
        let key = hash.finalize().to_vec();

        let secret_box = SecretBox::new(key, Salsa20).unwrap();
        match secret_box.unseal(ciphertext.ciphertext.as_slice(), nonce) {
            Some(plaintext) => match String::from_utf8(plaintext) {
                Ok(plaintext) => Some(plaintext),
                Err(_) => None,
            },
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::encrypt::PrivateKey;
    use fuzzytags::RootSecret;

    #[test]
    fn test_encrypt_to_tag() {
        let secret = PrivateKey::generate();
        let public_key = secret.public_key();

        let root_secret = RootSecret::<24>::generate();
        let tagging_key = root_secret.tagging_key();

        let ciphertext =
            public_key.encrypt(&tagging_key.generate_tag(), &String::from("Hello World"));

        let plaintext = secret.decrypt(&ciphertext);
        assert_eq!(plaintext.unwrap(), String::from("Hello World"))
    }
}
