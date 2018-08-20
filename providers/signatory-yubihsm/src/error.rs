/// Create a new error (of a given enum variant) with a formatted message
macro_rules! err {
    ($variant:ident, $msg:expr) => {
        ::signatory::error::Error::new(
            ::signatory::error::ErrorKind::$variant,
            Some($msg)
        )
    };
    ($variant:ident, $fmt:expr, $($arg:tt)+) => {
        err!($variant, &format!($fmt, $($arg)+))
    };
}

/// Create and return an error with a formatted message
macro_rules! fail {
    ($kind:ident, $msg:expr) => {
        return Err(err!($kind, $msg).into());
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(err!($kind, $fmt, $($arg)+).into());
    };
}
