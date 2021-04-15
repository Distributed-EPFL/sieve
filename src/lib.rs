#![deny(missing_docs)]

//! This crate provides an implementation of the `BatchedSieve` consistent broadcast algorithm. <br />
//! See the examples directory for examples on how to use this in your application

mod batched;
pub use batched::*;
