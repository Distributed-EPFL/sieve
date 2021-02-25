#![deny(missing_docs)]

//! This crate provides two implementation of the `Sieve` consistent broadcast algorithm

/// This module provides an implementation of basic `Sieve` supporting broadcast of single message.
pub mod classic;

/// This module provides an optimized version of `Sieve` using batching and selective acknowledgements, on
/// top of batched `Murmur`.
pub mod batched;
