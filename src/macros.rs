//! Signatory macros (for error handling)

#[allow(unused_macros)]

/// Create a new error (of a given enum variant) with a formatted message
#[cfg(not(feature = "std"))]
macro_rules! err {
    ($variant: ident, $msg: expr) => {
        ::error::Error::from(::error::ErrorKind::$variant)
    };
    ($variant: ident, $fmt: expr, $($arg: tt) +) => {
        ::error::Error::from(::error::ErrorKind::$variant)
    };
}

/// Create a new error (of a given enum variant) with a formatted message
#[cfg(feature = "std")]
macro_rules! err {
    ($variant:ident, $msg:expr) => {
        ::error::Error::new(
            ::error::ErrorKind::$variant,
            Some($msg)
        )
    };
    ($variant:ident, $fmt:expr, $($arg:tt)+) => {
        ::error::Error::new(
            ::error::ErrorKind::$variant,
            Some(&format!($fmt, $($arg)+))
        )
    };
}
