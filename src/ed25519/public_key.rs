//! Ed25519 public keys

/// Size of an Ed25519 public key in bytes (256-bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 public keys
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    #[allow(dead_code)]
    pub(crate) fn new(bytes: &[u8]) -> Self {
        if bytes.len() != PUBLIC_KEY_SIZE {
            panic!("public key is incorrect size: {}", bytes.len())
        }

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(bytes);
        PublicKey(public_key)
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
