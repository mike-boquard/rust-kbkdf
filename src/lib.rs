//! # Rust Implementation of NIST SP800-108 Key Based Key Derivation Function (KBKDF)
//!
//! This crate provides a Rust implementation of the [NIST SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)
//! standard for performing key-derivation based on a source key.
//!
//! This crate implements the KBKDF in the following modes:
//!
//! * Counter
//! * Feedback
//! * Double-Pipeline Iteration
//!
//! This crate was designed such that the user may provide their own Pseudo Random Function (as defined in Section 4 of
//! [SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)) via the implementation of
//! two traits:
//!
//! * [`PseudoRandomFunctionKey`]
//! * [`PseudoRandomFunction`]
//!
//! ## Psuedo Random Function Trait
//!
//! The purpose of the PRF trait is to allow a user to provide their own implementation of a PRF (as defined in Section 4
//! of [SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)).
//!
//! **Please note, that in order for an implementation of KBKDF to be NIST approved, an approved PRF must be used!**
//!
//! The author of this crate _does not_ guarantee that this implementation is NIST approved!
//!
//! ## Pseudo Random Function Key
//!
//! This trait is used to ensure that the implementation of the `PseudoRandomFunction` trait can access the necessary
//! source key in a way that passes Rust's borrow checker.
//!
//! ## Example
//!
//! An example of how to use the two traits are found in the `tests` module utilizing the [OpenSSL Crate](https://crates.io/crates/openssl).

// This list comes from
// https://github.com/rust-unofficial/patterns/blob/master/anti_patterns/deny-warnings.md
#![deny(
    bad_style,
    const_err,
    dead_code,
    improper_ctypes,
    rustdoc::missing_doc_code_examples,
    rustdoc::broken_intra_doc_links,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_copy_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![no_std]

use generic_array::{ArrayLength, GenericArray};
use typenum::ToInt;

use zeroize::Zeroize;

/// Defines how a PseudoRandomFunction handles a key
pub trait PseudoRandomFunctionKey {
    /// The key handle type this returns
    type KeyHandle;

    /// Returns the key handle held by this instance
    fn key_handle(&self) -> &Self::KeyHandle;
}

/// Defines how the KBKDF crate will interact with PRFs
/// This allows the user of this crate to provide their own implementation of a PRF, however, only
/// SP800-108 specified PRFs are allowed in the approved mode of operation.  Given that, this crate
/// cannot test for that and assumes that the user is using an approved PRF.
pub trait PseudoRandomFunction<'a> {
    /// The type kf key handle the PRF is expecting
    type KeyHandle;
    /// The PRF output size
    type PrfOutputSize: ArrayLength<u8> + ToInt<usize>;
    /// The error type returned
    type Error;

    /// Initializes the pseudo random function
    ///
    /// # Arguments
    ///
    /// * `key` - The key (K<sub>1</sub>)
    ///
    /// # Returns
    ///
    /// Either nothing or an [`Error`]
    ///
    /// # Panics
    ///
    /// This function is allowed to panic if [`init`](PseudoRandomFunction::init) is called while already initialized
    fn init(
        &mut self,
        key: &'a dyn PseudoRandomFunctionKey<KeyHandle = Self::KeyHandle>,
    ) -> Result<(), Self::Error>;

    /// Updates the PRF function
    ///
    /// # Arguments
    ///
    /// * `msg` - The next message to input into the PRF
    ///
    /// # Returns
    ///
    /// Either nothing or an [`Error`]
    ///
    /// # Panics
    ///
    /// This function is allowed to panic if [`update`](PseudoRandomFunction::update)
    /// is called before [`init`](PseudoRandomFunction::init)
    fn update(&mut self, msg: &[u8]) -> Result<(), Self::Error>;

    /// Finishes the PRF and returns the value in a buffer
    ///
    /// # Arguments
    ///
    /// * `out` - The result of the PRF
    ///
    /// # Returns
    ///
    /// Either nothing or an [`Error`]
    ///
    /// # Panics
    ///
    /// This function is allowed to panic if [`finish`](PseudoRandomFunction::finish)
    /// is called before [`init`](PseudoRandomFunction::init)
    fn finish(&mut self, out: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Counter mode options
#[derive(Copy, Clone, Debug)]
pub struct CounterMode {
    /// Length of the binary representation of the counter, in bits
    pub counter_length: usize,
}

/// Defines options for KDF in feedback mode
#[derive(Copy, Clone, Debug)]
pub struct FeedbackMode<'a> {
    /// Initial value used in first iteration of feedback mode
    pub iv: Option<&'a [u8]>,
    /// Length of the binary representation of the counter, in bits.  If not provided, counter unused
    pub counter_length: Option<usize>,
}

/// Defines options for KDF in double-pipeline iteration mode
#[derive(Copy, Clone, Debug)]
pub struct DoublePipelineIterationMode {
    /// Length of the binary representation of the counter, in bits.  If not provided, counter unused
    pub counter_length: Option<usize>,
}

/// Defines types and arguments for specific KDF modes
#[derive(Copy, Clone, Debug)]
pub enum KDFMode<'a> {
    /// KDF in counter mode (SP800-108 Section 5.1)
    CounterMode(CounterMode),
    /// KDF in feedback mode (SP800-108 Section 5.2)
    FeedbackMode(FeedbackMode<'a>),
    /// KDF in double-pipeline iteration mode (SP800-108 Section 5.3)
    DoublePipelineIterationMode(DoublePipelineIterationMode),
}

/// Used to set location of counter when using fixed input
#[derive(Copy, Clone, Debug)]
pub enum CounterLocation {
    /// No use for counter
    NoCounter,
    /// Counter before fixed input
    BeforeFixedInput,
    /// Before the iteration variable
    BeforeIter,
    /// Counter is placed at a specified bit location
    MiddleOfFixedInput(usize),
    /// Counter after fixed input
    AfterFixedInput,
    /// Counter after the iteration variable
    AfterIter,
}

/// Fixed input used when implementation is under test
#[derive(Debug)]
pub struct FixedInput<'a> {
    /// The fixed input
    pub fixed_input: &'a [u8],
    /// The location of the counter
    pub counter_location: CounterLocation,
}

/// Specified input for PRF
#[derive(Debug)]
pub struct SpecifiedInput<'a> {
    /// Identifies purpose of the derived keying material
    pub label: &'a [u8],
    /// Information related to the derived keying material
    pub context: &'a [u8],
}

/// The type of input.  May be a fixed input
#[derive(Debug)]
pub enum InputType<'a> {
    /// Fixed input with a specific counter location.  This should only be used when the implementation
    /// is undergoing ACVP testing (see <https://pages.nist.gov/ACVP/draft-celi-acvp-kbkdf.html#SP800-108>)
    FixedInput(FixedInput<'a>),
    /// Input specifying label and context
    SpecifiedInput(SpecifiedInput<'a>),
}

/// Performs [SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)
/// key-based key derivation function
///
/// # Inputs
///
/// * `kdf_mode` - Which mode the the derivation function will run in
/// * `input_type` - The type of input used to derive the key
/// * `key` - The base key to use to derive the key
/// * `prf` - The Pseudo-random function used to derive the key
/// * `derived_key` - The output key
///
/// # Panics
///
/// If invalid options are provided, this function will panic
pub fn kbkdf<'a, T: PseudoRandomFunction<'a>>(
    kdf_mode: &KDFMode,
    input_type: &InputType,
    key: &'a dyn PseudoRandomFunctionKey<KeyHandle = T::KeyHandle>,
    prf: &mut T,
    derived_key: &mut [u8],
) -> Result<(), T::Error> {
    match kdf_mode {
        KDFMode::CounterMode(counter_mode) => {
            kbkdf_counter::<T>(counter_mode, input_type, key, prf, derived_key)
        }
        KDFMode::FeedbackMode(feedback_mode) => {
            kbkdf_feedback::<T>(feedback_mode, input_type, key, prf, derived_key)
        }
        KDFMode::DoublePipelineIterationMode(double_pipeline) => {
            kbkdf_double_pipeline::<T>(double_pipeline, input_type, key, prf, derived_key)
        }
    }
}

fn kbkdf_counter<'a, T: PseudoRandomFunction<'a>>(
    counter_mode: &CounterMode,
    input_type: &InputType,
    key: &'a dyn PseudoRandomFunctionKey<KeyHandle = T::KeyHandle>,
    prf: &mut T,
    derived_key: &mut [u8],
) -> Result<(), T::Error> {
    // Step 1 -> n = CEIL(L/h)
    let n = calculate_counter(derived_key.len() * 8, T::PrfOutputSize::to_int() * 8);
    let mut intermediate_key = GenericArray::<u8, T::PrfOutputSize>::default();

    let length = (derived_key.len() as u32).to_be_bytes();
    assert!(
        n < 2_usize.pow(counter_mode.counter_length as u32),
        "Invalid derived key length"
    );
    for i in 1..=n {
        prf.init(key)?;
        let counter = i.to_be_bytes();
        let counter = &counter[(counter.len() - counter_mode.counter_length / 8)..];
        match input_type {
            InputType::FixedInput(fixed_input) => match fixed_input.counter_location {
                CounterLocation::NoCounter => prf.update(fixed_input.fixed_input)?,
                CounterLocation::BeforeFixedInput => {
                    prf.update(counter)?;
                    prf.update(fixed_input.fixed_input)?;
                }
                CounterLocation::MiddleOfFixedInput(position) => {
                    prf.update(&fixed_input.fixed_input[..position])?;
                    prf.update(counter)?;
                    prf.update(&fixed_input.fixed_input[position..])?;
                }
                CounterLocation::AfterFixedInput => {
                    prf.update(fixed_input.fixed_input)?;
                    prf.update(counter)?;
                }
                _ => panic!(
                    "Invalid counter location for KBKDF In Counter Mode: {:?}",
                    fixed_input.counter_location
                ),
            },
            InputType::SpecifiedInput(specified_input) => {
                prf.update(counter)?;
                prf.update(specified_input.label)?;
                prf.update(b"0")?;
                prf.update(specified_input.context)?;
                prf.update(&length)?;
            }
        }
        let _ = prf.finish(intermediate_key.as_mut_slice())?;
        insert_result(i, intermediate_key.as_slice(), derived_key);
        intermediate_key.zeroize();
    }

    Ok(())
}

fn kbkdf_double_pipeline<'a, T: PseudoRandomFunction<'a>>(
    double_feedback: &DoublePipelineIterationMode,
    input_type: &InputType,
    key: &'a dyn PseudoRandomFunctionKey<KeyHandle = T::KeyHandle>,
    prf: &mut T,
    derived_key: &mut [u8],
) -> Result<(), T::Error> {
    let n = calculate_counter(derived_key.len() * 8, T::PrfOutputSize::to_int() * 8);
    let mut intermediate_key = GenericArray::<u8, T::PrfOutputSize>::default();
    let mut feedback = GenericArray::<u8, T::PrfOutputSize>::default();
    let length = (derived_key.len() as u32).to_be_bytes();
    assert!(
        n < 2_usize.pow(32),
        "Invalid length provided for derived key"
    );
    for i in 1..=n {
        let counter = i.to_be_bytes();
        let counter = feedback_counter(double_feedback.counter_length, counter.as_slice());
        // First calculate feedback, if the first iteration use the provided input vaalue
        prf.init(key)?;
        if i == 1 {
            match input_type {
                InputType::FixedInput(fixed_input) => {
                    prf.update(fixed_input.fixed_input)?;
                }
                InputType::SpecifiedInput(specified_input) => {
                    prf.update(specified_input.label)?;
                    prf.update(b"0")?;
                    prf.update(specified_input.context)?;
                    prf.update(length.as_slice())?;
                }
            }
        } else {
            prf.update(feedback.as_slice())?;
        }
        let _ = prf.finish(feedback.as_mut_slice())?;

        prf.init(key)?;

        match input_type {
            InputType::FixedInput(fixed_input) => match fixed_input.counter_location {
                CounterLocation::NoCounter => {
                    prf.update(feedback.as_slice())?;
                    prf.update(fixed_input.fixed_input)?;
                }
                CounterLocation::BeforeIter => {
                    prf.update(
                        counter
                            .expect("Counter length not provided for BeforeIter counter location"),
                    )?;
                    prf.update(feedback.as_slice())?;
                    prf.update(fixed_input.fixed_input)?;
                }
                CounterLocation::AfterFixedInput => {
                    prf.update(feedback.as_slice())?;
                    prf.update(fixed_input.fixed_input)?;
                    prf.update(counter.expect(
                        "Counter length not provided for AfterFixedInput counter location",
                    ))?;
                }
                CounterLocation::AfterIter => {
                    prf.update(feedback.as_slice())?;
                    prf.update(
                        counter
                            .expect("Counter length not provided for AfterIter counter location"),
                    )?;
                    prf.update(fixed_input.fixed_input)?;
                }
                _ => panic!(
                    "Invalid counter location for double feedback: {:?}",
                    fixed_input.counter_location
                ),
            },
            InputType::SpecifiedInput(specified_input) => {
                prf.update(feedback.as_slice())?;
                if let Some(counter) = counter {
                    prf.update(counter)?;
                }
                prf.update(specified_input.label)?;
                prf.update(b"0")?;
                prf.update(specified_input.context)?;
                prf.update(&length)?;
            }
        }

        let _ = prf.finish(intermediate_key.as_mut_slice())?;
        insert_result(i, intermediate_key.as_slice(), derived_key);
        intermediate_key.zeroize();
    }

    Ok(())
}

fn kbkdf_feedback<'a, T: PseudoRandomFunction<'a>>(
    feedback_mode: &FeedbackMode,
    input_type: &InputType,
    key: &'a dyn PseudoRandomFunctionKey<KeyHandle = T::KeyHandle>,
    prf: &mut T,
    derived_key: &mut [u8],
) -> Result<(), T::Error> {
    let n = calculate_counter(derived_key.len() * 8, T::PrfOutputSize::to_int() * 8);
    let mut intermediate_key = GenericArray::<u8, T::PrfOutputSize>::default();
    let mut has_intermediate = feedback_mode.iv.is_some();
    if let Some(iv) = feedback_mode.iv {
        assert_eq!(iv.len(), T::PrfOutputSize::to_int());
        intermediate_key.copy_from_slice(iv);
    }
    let length = (derived_key.len() as u32).to_be_bytes();
    assert!(n < 2_usize.pow(32), "Invalid derived_key length provided");
    for i in 1..=n {
        prf.init(key)?;
        let counter = i.to_be_bytes();
        let counter = feedback_counter(feedback_mode.counter_length, counter.as_slice());
        match input_type {
            InputType::FixedInput(fixed_input) => match fixed_input.counter_location {
                CounterLocation::NoCounter => {
                    if has_intermediate {
                        prf.update(intermediate_key.as_slice())?;
                    }
                    prf.update(fixed_input.fixed_input)?;
                }
                CounterLocation::BeforeIter => {
                    prf.update(
                        counter
                            .expect("Counter length not provided for BeforeIter counter location"),
                    )?;
                    if has_intermediate {
                        prf.update(intermediate_key.as_slice())?;
                    }
                    prf.update(fixed_input.fixed_input)?;
                }
                CounterLocation::AfterIter => {
                    if has_intermediate {
                        prf.update(intermediate_key.as_slice())?;
                    }
                    prf.update(
                        counter
                            .expect("Counter length not provided for AfterIter counter location"),
                    )?;
                    prf.update(fixed_input.fixed_input)?;
                }
                CounterLocation::AfterFixedInput => {
                    if has_intermediate {
                        prf.update(intermediate_key.as_slice())?;
                    }
                    prf.update(fixed_input.fixed_input)?;
                    prf.update(counter.expect(
                        "Counter length not provided for AfterFixedInput counter location",
                    ))?;
                }
                _ => panic!(
                    "Invalid counter location provided for KDF feedback mode: {:?}",
                    fixed_input.counter_location
                ),
            },
            InputType::SpecifiedInput(specified_input) => {
                if has_intermediate {
                    prf.update(intermediate_key.as_slice())?;
                }
                if let Some(counter) = counter {
                    prf.update(counter)?;
                }
                prf.update(specified_input.label)?;
                prf.update(b"0")?;
                prf.update(specified_input.context)?;
                prf.update(&length)?;
            }
        }
        let _ = prf.finish(intermediate_key.as_mut_slice())?;
        insert_result(i, intermediate_key.as_slice(), derived_key);
        has_intermediate = true;
    }

    Ok(())
}

fn calculate_counter(derived_key_len_bits: usize, prf_output_size_in_bits: usize) -> usize {
    derived_key_len_bits / prf_output_size_in_bits
        + if derived_key_len_bits % prf_output_size_in_bits != 0 {
            1
        } else {
            0
        }
}

fn feedback_counter(counter_length: Option<usize>, counter: &[u8]) -> Option<&[u8]> {
    match counter_length {
        None => None,
        Some(length) => Some(&counter[(counter.len() - length / 8)..]),
    }
}

fn insert_result(counter: usize, intermediate: &[u8], result: &mut [u8]) {
    let low_index = (counter - 1) * intermediate.len();
    assert!(
        low_index < result.len(),
        "The starting insert index should not exceed bounds of result slice"
    );
    let high_index = core::cmp::min(low_index + intermediate.len(), result.len());
    assert!(
        high_index <= result.len(),
        "Ending insert index should not exceed bounds of result slice"
    );
    result[low_index..high_index].clone_from_slice(&intermediate[..(high_index - low_index)]);
}
