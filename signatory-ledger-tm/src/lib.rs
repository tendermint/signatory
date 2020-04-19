//! ledger-tm provider: Ledger Tendermint Validator app (Ed25519 signatures for amino votes)

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/iqlusioninc/signatory/develop/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-ledger-tm/0.19.0"
)]

use ledger_tendermint::ledgertm::TendermintValidatorApp;
use signatory::{
    ed25519::{PublicKey, Signature},
    public_key::PublicKeyed,
    signature::{Error, Signer},
};
use std::sync::{Arc, Mutex};

/// ed25519 signature provider for the Ledger Tendermint Validator app
pub struct Ed25519LedgerTmAppSigner {
    app: Arc<Mutex<TendermintValidatorApp>>,
}

impl Ed25519LedgerTmAppSigner {
    /// Create a new Ed25519 signer based on Ledger Nano S - Tendermint Validator app
    pub fn connect() -> Result<Self, Error> {
        let validator_app = TendermintValidatorApp::connect().map_err(Error::from_source)?;
        let app = Arc::new(Mutex::new(validator_app));
        let signer = Ed25519LedgerTmAppSigner { app };
        let _pk = signer.public_key().unwrap();
        Ok(signer)
    }
}

impl PublicKeyed<PublicKey> for Ed25519LedgerTmAppSigner {
    /// Returns the public key that corresponds to the Tendermint Validator app connected to this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        let app = self.app.lock().unwrap();
        let pk = app.public_key().map_err(Error::from_source)?;
        Ok(PublicKey(pk))
    }
}

impl Signer<Signature> for Ed25519LedgerTmAppSigner {
    /// c: Compute a compact, fixed-sized signature of the given amino/json vote
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let app = self.app.lock().unwrap();
        let sig = app.sign(&msg).map_err(Error::from_source)?;
        Ok(Signature::from(sig))
    }
}

#[cfg(test)]
mod tests {
    use crate::Ed25519LedgerTmAppSigner;

    #[test]
    fn public_key() {
        use signatory::public_key::PublicKeyed;
        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        let _pk = signer.public_key().unwrap();
        println!("PK {:0X?}", _pk);
    }

    #[test]
    fn sign() {
        use crate::Ed25519LedgerTmAppSigner;
        use signatory::signature::Signer;

        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Sign message1
        let some_message1 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x10, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message1);
    }

    #[test]
    fn sign2() {
        use signatory::signature::Signer;

        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Sign message1
        let some_message1 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message1);

        // Sign message2
        let some_message2 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x10, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message2);
    }

    #[test]
    fn sign_many() {
        use signatory::public_key::PublicKeyed;
        use signatory::signature::Signer;
        use Ed25519LedgerTmAppSigner;

        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Get public key to initialize
        let _pk = signer.public_key().unwrap();
        println!("PK {:0X?}", _pk);

        for index in 50u8..254u8 {
            // Sign message1
            let some_message = [
                33, 0x8,  // (field_number << 3) | wire_type
                0x1,  // PrevoteType
                0x11, // (field_number << 3) | wire_type
                0x40, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
                0x19, // (field_number << 3) | wire_type
                index, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
                0x22, // (field_number << 3) | wire_type
                // remaining fields (timestamp):
                0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
            ];

            signer.sign(&some_message);
        }
    }
}
