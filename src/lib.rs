#![deny(missing_docs)]

//! This crate provides an implementation of the [`Sieve`] consistent broadcast algorithm. <br />
//! See the examples directory for examples on how to use this in your application
//!
//! [`Sieve`]: self::Sieve

mod batched;
pub use batched::*;
