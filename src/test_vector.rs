//! Test vector structure for signatures

#[cfg(feature = "alloc")]
mod pkcs8;

#[cfg(feature = "alloc")]
pub use pkcs8::ToPkcs8;

/// Signature test vector
pub struct TestVector {
    /// Algorithm name
    pub alg: TestVectorAlgorithm,

    /// Secret key (i.e. seed)
    pub sk: &'static [u8],

    /// Public key in compressed Edwards-y form
    pub pk: &'static [u8],

    /// Random nonce value (i.e. ECDSA's `k` value)
    pub nonce: Option<&'static [u8]>,

    /// Message to be signed
    pub msg: &'static [u8],

    /// Expected signature
    pub sig: &'static [u8],

    /// Expected to pass or fail
    pub pass: bool,
}

/// Algorithms for which we have test vectors
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TestVectorAlgorithm {
    /// NIST P-256 (a.k.a. prime256v1, secp256r1) elliptic curve
    NistP256,

    /// NIST P-384 (a.k.a. secp384r1) elliptic curve
    NistP384,

    /// secp256k1 elliptic curve
    Secp256k1,

    /// "edwards25519" elliptic curve
    Ed25519,
}
