//! Ed25519 seeds: 32-bit uniformly random secret value used to derive scalars
//! and nonce prefixes

use clear_on_drop::clear::Clear;
use rand::{CryptoRng, OsRng, RngCore};

use error::Error;

/// Size of the "seed" value for an Ed25519 private key
pub const SEED_SIZE: usize = 32;

/// Size of an Ed25519 keypair (private scalar + compressed Edwards-y public key)
pub const KEYPAIR_SIZE: usize = 64;

/// Ed25519 seeds: derivation secrets for Ed25519 private scalars/nonce prefixes
pub struct Seed(pub(crate) [u8; SEED_SIZE]);

impl Seed {
    /// Generate a new Ed25519 seed using the operating system's
    /// cryptographically secure random number generator
    pub fn generate() -> Self {
        let mut csprng = OsRng::new().expect("RNG initialization failure!");
        Self::generate_from_rng::<OsRng>(&mut csprng)
    }

    /// Generate a new Ed25519 seed using the provided random number generator
    pub fn generate_from_rng<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let mut bytes = [0u8; SEED_SIZE];
        csprng.fill_bytes(&mut bytes[..]);
        Self::new(bytes)
    }

    /// Create an Ed25519 seed from a 32-byte array
    pub fn new(bytes: [u8; SEED_SIZE]) -> Self {
        Seed(bytes)
    }

    /// Create an Ed25519 seed from a byte slice, returning `KeyInvalid` if the
    /// slice is not the correct size (32-bytes)
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        ensure!(
            slice.len() == SEED_SIZE,
            KeyInvalid,
            "invalid {}-byte seed (expected {})",
            slice.len(),
            SEED_SIZE
        );

        let mut bytes = [0u8; SEED_SIZE];
        bytes.copy_from_slice(slice);

        Ok(Seed::new(bytes))
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
        Self::from_slice(&keypair[..SEED_SIZE])
    }

    /// Expose the secret values of the `Seed` as a byte slice
    pub fn as_secret_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.clear()
    }
}

impl From<[u8; 32]> for Seed {
    fn from(bytes: [u8; SEED_SIZE]) -> Self {
        Seed::new(bytes)
    }
}
