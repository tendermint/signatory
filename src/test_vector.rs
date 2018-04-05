//! Test vector structure for signatures

/// Signature test vector
pub struct TestVector {
    /// Secret key (i.e. seed)
    pub sk: &'static [u8],

    /// Public key in compressed Edwards-y form
    pub pk: &'static [u8],

    /// Message to be signed
    pub msg: &'static [u8],

    /// Expected signature
    pub sig: &'static [u8],
}
