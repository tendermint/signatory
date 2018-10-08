//! Ed25519 provider for the ledger cosmos validator app

#![crate_name = "signatory_ledger_cosval"]
#![crate_type = "lib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-ledger-cosval/0.9.0"
)]

extern crate ledger_cosmos;
extern crate signatory;

use std::sync::Arc;
use std::sync::Mutex;

use signatory::{
    ed25519::{PublicKey, Signature},
    error::{Error, ErrorKind},
    PublicKeyed, Signer,
};

/// ed25519 signature provider for the ledger cosmos validator app
#[allow(dead_code)]
pub struct Ed25519CosmosAppSigner {
    app: Arc<Mutex<ledger_cosmos::CosmosValidatorApp>>,
}

impl Ed25519CosmosAppSigner {
    /// Create a new ed25519 signer based on ledger nano s - cosmos validator app
    pub fn connect() -> Result<Self, Error> {
        // TODO: Maybe use this to pass other derivation path

        match ledger_cosmos::CosmosValidatorApp::connect() {
            Ok(validator_app) => {
                let app = Arc::new(Mutex::new(validator_app));
                Ok(Ed25519CosmosAppSigner { app })
            }
            Err(err) => Err(Error::new(ErrorKind::ProviderError, Some(&err.to_string()))),
        }
    }
}

impl PublicKeyed<PublicKey> for Ed25519CosmosAppSigner {
    /// Returns the public key that corresponds cosmos validator app connected to this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        let app = self.app.lock().unwrap();

        match app.public_key() {
            Ok(pk) => Ok(PublicKey(pk)),
            Err(err) => Err(Error::new(ErrorKind::ProviderError, Some(&err.to_string()))),
        }
    }
}

impl Signer<Signature> for Ed25519CosmosAppSigner {
    /// c: Compute a compact, fixed-sized signature of the given amino/json vote
    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let app = self.app.lock().unwrap();

        match app.sign(&msg) {
            Ok(sig) => Ok(Signature(sig)),
            Err(err) => Err(Error::new(ErrorKind::ProviderError, Some(&err.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: Improve tests once amino schema is defined

    #[test]
    fn public_key() {
        use signatory::PublicKeyed;
        use Ed25519CosmosAppSigner;
        let signer = Ed25519CosmosAppSigner::connect().unwrap();

        let _pk = signer.public_key().unwrap();
    }

    #[test]
    fn sign() {
        use signatory::Signer;
        use Ed25519CosmosAppSigner;

        let signer = Ed25519CosmosAppSigner::connect().unwrap();
        let some_message1 = b"{\"height\":1,\"other\":\"Some dummy data\",\"round\":0}";
        let _sig = signer.sign(some_message1).unwrap();
    }
}
