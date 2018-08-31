//! Abstract Syntax Notation One (ASN.1) support.
//! Presently specialized for Distinguished Encoding Rules (DER)

/// ASN.1 tags
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Tag {
    /// ASN.1 `INTEGER`
    Integer = 0x02,

    /// ASN.1 `SEQUENCE`: lists of other elements
    Sequence = 0x30,
}
