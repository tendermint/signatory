//! Abstract Syntax Notation One (ASN.1) support.
//! Presently specialized for Distinguished Encoding Rules (DER)

// TODO: this code could probably benefit from some refactoring

/// ASN.1 types
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Type {
    /// ASN.1 `INTEGER`
    Integer,

    /// ASN.1 `SEQUENCE`: lists of other elements
    Sequence,
}

impl Type {
    /// ASN.1 tag value for this type
    pub fn tag(&self) -> u8 {
        match self {
            Type::Integer => 0x02,
            Type::Sequence => 0x30,
        }
    }
}
