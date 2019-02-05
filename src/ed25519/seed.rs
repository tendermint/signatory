//! Ed25519 seeds: 32-bit uniformly random secret value used to derive scalars
//! and nonce prefixes

#[cfg(feature = "encoding")]
use crate::encoding::Decode;
use crate::error::Error;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use crate::{encoding::Encode, prelude::*};
#[cfg(feature = "rand_os")]
use rand_os::{
    rand_core::{CryptoRng, RngCore},
    OsRng,
};
#[cfg(feature = "encoding")]
use subtle_encoding::Encoding;
use zeroize::Zeroize;

/// Size of the "seed" value for an Ed25519 private key
pub const SEED_SIZE: usize = 32;

/// Size of an Ed25519 keypair (private scalar + compressed Edwards-y public key)
pub const KEYPAIR_SIZE: usize = 64;

/// Ed25519 seeds: derivation secrets for Ed25519 private scalars/nonce prefixes
#[derive(Clone)]
pub struct Seed(pub [u8; SEED_SIZE]);

impl Seed {
    /// Create an Ed25519 seed from a 32-byte array
    pub fn new(bytes: [u8; SEED_SIZE]) -> Self {
        Seed(bytes)
    }

    /// Generate a new Ed25519 seed using the operating system's
    /// cryptographically secure random number generator
    #[cfg(feature = "rand_os")]
    pub fn generate() -> Self {
        let mut csprng = OsRng::new().expect("RNG initialization failure!");
        Self::generate_from_rng::<OsRng>(&mut csprng)
    }

    /// Generate a new Ed25519 seed using the provided random number generator
    #[cfg(feature = "rand_os")]
    pub fn generate_from_rng<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut bytes = [0u8; SEED_SIZE];
        csprng.fill_bytes(&mut bytes[..]);
        Self::new(bytes)
    }

    /// Create an Ed25519 seed from a byte slice, returning `KeyInvalid` if the
    /// slice is not the correct size (32-bytes)
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        ensure!(
            bytes.as_ref().len() == SEED_SIZE,
            KeyInvalid,
            "expected {}-byte seed (got {})",
            SEED_SIZE,
            bytes.as_ref().len()
        );

        let mut seed = [0u8; SEED_SIZE];
        seed.copy_from_slice(bytes.as_ref());

        Ok(Seed::new(seed))
    }

    /// Create an Ed25519 seed from a keypair: i.e. a seed and its assocaited
    /// public key (i.e. compressed Edwards-y coordinate)
    pub fn from_keypair(keypair: &[u8]) -> Result<Self, Error> {
        ensure!(
            keypair.len() == KEYPAIR_SIZE,
            KeyInvalid,
            "invalid {}-byte keypair (expected {})",
            keypair.len(),
            KEYPAIR_SIZE
        );

        // TODO: ensure public key part of keypair is correct
        Self::from_bytes(&keypair[..SEED_SIZE])
    }

    /// Decode a `Seed` from an encoded (hex or Base64) Ed25519 keypair
    #[cfg(feature = "encoding")]
    pub fn decode_keypair<E: Encoding>(
        encoded_keypair: &[u8],
        encoding: &E,
    ) -> Result<Self, Error> {
        let mut decoded_keypair = [0u8; SEED_SIZE * 2];
        let decoded_len = encoding.decode_to_slice(encoded_keypair, &mut decoded_keypair)?;

        ensure!(
            decoded_len == SEED_SIZE * 2,
            KeyInvalid,
            "malformed keypair (incorrect length)"
        );

        Self::from_keypair(&decoded_keypair)
    }

    /// Expose the secret values of the `Seed` as a byte slice
    pub fn as_secret_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "encoding")]
impl Decode for Seed {
    /// Decode an Ed25519 seed from a byte slice with the given encoding (e.g. hex, Base64)
    fn decode<E: Encoding>(encoded_seed: &[u8], encoding: &E) -> Result<Self, Error> {
        let mut decoded_seed = [0u8; SEED_SIZE];
        let decoded_len = encoding.decode_to_slice(encoded_seed, &mut decoded_seed)?;

        ensure!(
            decoded_len == SEED_SIZE,
            KeyInvalid,
            "invalid {}-byte seed (expected {})",
            decoded_len,
            SEED_SIZE
        );

        Ok(Self::new(decoded_seed))
    }
}

#[cfg(all(feature = "encoding", feature = "alloc"))]
impl Encode for Seed {
    /// Encode an Ed25519 seed with the given encoding (e.g. hex, Base64)
    fn encode<E: Encoding>(&self, encoding: &E) -> Vec<u8> {
        encoding.encode(self.as_secret_slice())
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<[u8; 32]> for Seed {
    fn from(bytes: [u8; SEED_SIZE]) -> Self {
        Seed::new(bytes)
    }
}
