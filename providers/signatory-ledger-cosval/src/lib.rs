//! Ed25519 provider for the ledger cosmos validator app

#![crate_name = "signatory_ledger_cosval"]
#![crate_type = "lib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
html_root_url = "https://docs.rs/signatory-ledger-cosval/0.0.1"
)]

extern crate signatory;
extern crate ledger_cosmos_rs;

use std::sync::Mutex;
use std::sync::Arc;

use signatory::{
    ed25519::Ed25519Signature,
    ed25519::PublicKey,
    generic_array::{typenum::U32, GenericArray},
    error::{Error, ErrorKind},
    PublicKeyed,
    Signer,
};

/// ed25519 signature provider for the ledger cosmos validator app
#[allow(dead_code)]
pub struct Ed25519CosmosAppSigner {
    app: Arc<Mutex<ledger_cosmos_rs::CosmosValidatorApp>>
}

impl Ed25519CosmosAppSigner {
    /// Create a new ed25519 signer based on ledger nano s - cosmos validator app
    pub fn connect() -> Result<Self, Error> {
        // TODO: Maybe use this to pass other derivation path

        match ledger_cosmos_rs::CosmosValidatorApp::connect() {
            Ok(_x) => {
                let app = Arc::new(Mutex::new(_x));
                Ok(Ed25519CosmosAppSigner { app })
            },
            Err(err) => Err(
                Error::new(ErrorKind::ProviderError, Some(&err.to_string()))
            )
        }
    }
}

impl PublicKeyed<PublicKey> for Ed25519CosmosAppSigner {
    /// Returns the public key that corresponds cosmos validator app connected to this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        let app = self.app.lock().unwrap();

        match app.public_key() {
            Ok(pk) => Ok(PublicKey(pk)),
            Err(err) => Err(
                Error::new(ErrorKind::ProviderError, Some(&err.to_string()))
            )
        }
    }
}

impl Signer<GenericArray<u8, U32>, Ed25519Signature> for Ed25519CosmosAppSigner {
    /// c: Compute a compact, fixed-sized signature of the given 32-byte SHA-256 digest
    fn sign(&self, msg: GenericArray<u8, U32>) -> Result<Ed25519Signature, Error> {
        let app = self.app.lock().unwrap();

        match app.sign(&msg) {
            Ok(sig) => Ok(Ed25519Signature(sig)),
            Err(_x) => Err(
                Error::new(ErrorKind::ProviderError, Some("Unknown"))
            )
        }
    }
}

// TODO: test against actual test vectors, rather than just checking if signatures roundtrip

#[cfg(test)]
mod tests {
    #[test]
    fn public_key() {
        use Ed25519CosmosAppSigner;
        use signatory::PublicKeyed;
        let signer = Ed25519CosmosAppSigner::connect().unwrap();

        let _pk = signer.public_key().unwrap();
    }

    #[test]
    fn sign() {
        use Ed25519CosmosAppSigner;
        use signatory::Signer;
        use signatory::generic_array::GenericArray;

        let signer = Ed25519CosmosAppSigner::connect().unwrap();

        let some_message1 = b"{\"height\":1,\"other\":\"Some dummy data\",\"round\":0}";
        let genarr = GenericArray::clone_from_slice(some_message1);

        let _sig = signer.sign(genarr).unwrap();
    }
}
