//! Abstract Syntax Notation One (ASN.1) constants

/// Tag numbers for ASN.1 types
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Tag {
    BitString = 0x03,
    OctetString = 0x04,
}
