//! Miscellaneous utility functions

use core::fmt;

#[allow(dead_code)]
pub(crate) fn fmt_colon_delimited_hex<B>(f: &mut fmt::Formatter, bytes: B) -> fmt::Result
where
    B: AsRef<[u8]>,
{
    let len = bytes.as_ref().len();

    for (i, byte) in bytes.as_ref().iter().enumerate() {
        write!(f, "{:02x}", byte)?;

        if i != len - 1 {
            write!(f, ":")?;
        }
    }

    Ok(())
}
