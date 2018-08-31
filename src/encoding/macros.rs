//! Macros for performing arithmetic which checks for overflow/underflow in
//! in a more succinct manner

#![allow(unused_macros)]

/// Checked addition
macro_rules! add {
    ($a:expr, $b:expr) => {
        $a.checked_add($b).expect("overflow")
    };
}

/// Checked subtraction
macro_rules! sub {
    ($a:expr, $b:expr) => {
        $a.checked_sub($b).expect("underflow")
    };
}

/// Checked multiplication
macro_rules! mul {
    ($a:expr, $b:expr) => {
        $a.checked_mul($b).expect("overflow")
    };
}

/// Checked division
macro_rules! div {
    ($a:expr, $b:expr) => {
        $a.checked_div($b).expect("overflow")
    };
}

/// Checked right shift
macro_rules! shr {
    ($a:expr, $b:expr) => {
        $a.checked_shr($b).expect("overflow")
    };
}

/// Checked left shift
macro_rules! shl {
    ($a:expr, $b:expr) => {
        $a.checked_shl($b).expect("overflow")
    };
}
