/// Create a new error (of a given enum variant) with a formatted message
#[cfg(not(feature = "std"))]
macro_rules! err {
    ($variant:ident, $msg:expr) => {
        ::signatory::error::Error::from(::signatory::error::ErrorKind::$variant)
    };
}

/// Create a new error (of a given enum variant) with a formatted message
#[cfg(feature = "std")]
macro_rules! err {
    ($variant:ident, $msg:expr) => {
        ::signatory::error::Error::new(::signatory::error::ErrorKind::$variant, Some($msg))
    };
}
