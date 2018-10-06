use std::sync::{Mutex, MutexGuard};
use yubihsm::Connector;
#[cfg(feature = "http")]
use yubihsm::HttpConnector;
#[cfg(feature = "mockhsm")]
use yubihsm::MockHsm;
#[cfg(feature = "usb")]
use yubihsm::UsbConnector;

use signatory_yubihsm::Session;

lazy_static! {
    static ref HSM_SESSION: Mutex<Session> =
        { Mutex::new(Session::create(create_hsm_connector(), Default::default()).unwrap()) };
}

/// Create a `signatory_yubihsm::Session` to run the test suite against
pub fn get_session() -> MutexGuard<'static, Session> {
    HSM_SESSION.lock().unwrap()
}

/// Create a `yubihsm::Connector` for accessing the HSM
///
/// Connector is selected by preference based on cargo features.
/// The preference order is:
///
/// 1. `mockhsm`
/// 2. `usb`
/// 3. `http`
///
/// Panics if none of the above features are enabled
#[allow(unreachable_code)]
pub fn create_hsm_connector() -> Box<Connector> {
    // MockHSM has highest priority when testing
    #[cfg(feature = "mockhsm")]
    return create_mockhsm_connector();

    // USB has second highest priority when testing
    #[cfg(feature = "usb")]
    return create_usb_connector();

    // HTTP has lowest priority when testing
    #[cfg(feature = "http")]
    return create_http_connector();

    panic!(
        "No connector features enabled! Enable one of these cargo features: \
         http, usb, mockhsm"
    );
}

/// Connect to the HSM via HTTP using `yubihsm-connector`
#[cfg(feature = "http")]
pub fn create_http_connector() -> Box<Connector> {
    HttpConnector::new(&Default::default()).unwrap().into()
}

/// Connect to the HSM via USB
#[cfg(feature = "usb")]
pub fn create_usb_connector() -> Box<Connector> {
    UsbConnector::new(&Default::default()).unwrap().into()
}

/// Create a mock HSM for testing in situations where a hardware device is
/// unavailable/impractical (e.g. CI)
#[cfg(feature = "mockhsm")]
pub fn create_mockhsm_connector() -> Box<Connector> {
    MockHsm::default().into()
}
