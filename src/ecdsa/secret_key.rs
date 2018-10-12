//! Raw ECDSA secret keys: `x` value for ECDSA.

use core::marker::PhantomData;
use generic_array::{typenum::Unsigned, GenericArray};
#[cfg(all(feature = "rand", feature = "std"))]
use rand::{CryptoRng, OsRng, RngCore};
#[cfg(feature = "encoding")]
use subtle_encoding::Encoding;
use zeroize::Zeroize;

use curve::WeierstrassCurve;
#[cfg(feature = "encoding")]
use encoding::Decode;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use encoding::Encode;
use error::Error;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use prelude::*;

/// Raw ECDSA secret keys: raw scalar value `WeierstrassCurve::ScalarBytes`
/// in size used as the `x` value for ECDSA.
pub struct SecretKey<C: WeierstrassCurve> {
    /// Byte serialization of a secret scalar for ECDSA
    bytes: GenericArray<u8, C::ScalarSize>,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C> SecretKey<C>
where
    C: WeierstrassCurve,
{
    /// Create a raw ECDSA secret key
    pub fn new<B>(into_bytes: B) -> Self
    where
        B: Into<GenericArray<u8, C::ScalarSize>>,
    {
        Self {
            bytes: into_bytes.into(),
            curve: PhantomData,
        }
    }

    /// Decode a raw ECDSA secret key from the given byte slice
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        let slice = bytes.as_ref();
        let length = slice.len();

        if length == C::ScalarSize::to_usize() {
            Ok(Self::new(GenericArray::clone_from_slice(slice)))
        } else {
            fail!(
                KeyInvalid,
                "invalid length for {:?} secret key: {}",
                C::CURVE_KIND,
                length
            );
        }
    }

    /// Generate a new ECDSA secret key using the operating system's
    /// cryptographically secure random number generator
    #[cfg(all(feature = "rand", feature = "std"))]
    pub fn generate() -> Self {
        let mut csprng = OsRng::new().expect("RNG initialization failure!");
        Self::generate_from_rng::<OsRng>(&mut csprng)
    }

    /// Generate a new ECDSA secret key using the provided random number generator
    #[cfg(feature = "rand")]
    pub fn generate_from_rng<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let mut bytes = GenericArray::default();
        csprng.fill_bytes(bytes.as_mut_slice());

        Self {
            bytes,
            curve: PhantomData,
        }
    }

    /// Expose this `SecretKey` as a byte slice
    pub fn as_secret_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C: WeierstrassCurve> Clone for SecretKey<C> {
    fn clone(&self) -> Self {
        Self::new(self.bytes.clone())
    }
}

#[cfg(feature = "encoding")]
impl<C> Decode for SecretKey<C>
where
    C: WeierstrassCurve,
{
    /// Decode an Ed25519 seed from a byte slice with the given encoding (e.g. hex, Base64)
    fn decode<E: Encoding>(encoded_key: &[u8], encoding: &E) -> Result<Self, Error> {
        let mut bytes = GenericArray::default();
        let decoded_len = encoding.decode_to_slice(encoded_key, &mut bytes)?;

        ensure!(
            decoded_len == C::ScalarSize::to_usize(),
            KeyInvalid,
            "invalid {}-byte seed (expected {})",
            decoded_len,
            C::ScalarSize::to_usize()
        );

        Ok(Self {
            bytes,
            curve: PhantomData,
        })
    }
}

#[cfg(all(feature = "encoding", feature = "alloc"))]
impl<C> Encode for SecretKey<C>
where
    C: WeierstrassCurve,
{
    /// Encode an Ed25519 seed with the given encoding (e.g. hex, Base64)
    fn encode<E: Encoding>(&self, encoding: &E) -> Vec<u8> {
        encoding.encode(self.as_secret_slice())
    }
}

impl<C> Drop for SecretKey<C>
where
    C: WeierstrassCurve,
{
    fn drop(&mut self) {
        self.bytes.as_mut().zeroize();
    }
}
