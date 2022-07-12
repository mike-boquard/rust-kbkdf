# Rust Implementation of NIST SP800-108 Key Based Key Derivation Function (KBKDF)

This crate provides a Rust implementation of the [NIST SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)
standard for performing key-derivation based on a source key.

This crate implements the KBKDF in the following modes:

* Counter
* Feedback
* Double-Pipeline Iteration

This crate was designed such that the user may provide their own Pseudo Random Function (as defined in Section 4 of
[SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)) via the implementation of
two traits:

* [`PseudoRandomFunctionKey`]
* [`PseudoRandomFunction`]

## Psuedo Random Function Trait

The purpose of the PRF trait is to allow a user to provide their own implementation of a PRF (as defined in Section 4
of [SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)).

**Please note, that in order for an implementation of KBKDF to be NIST approved, an approved PRF must be used!**

The author of this crate _does not_ guarantee that this implementation is NIST approved!

## Pseudo Random Function Key

This trait is used to ensure that the implementation of the `PseudoRandomFunction` trait can access the necessary
source key in a way that passes Rust's borrow checker.

## Example

An example of how to use the two traits are found in the `tests` module utilizing the [OpenSSL Crate](https://crates.io/crates/openssl).