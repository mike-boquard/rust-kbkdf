//! Rust implementation of NIST SP800-108 KBKDF

// This list comes from
// https://github.com/rust-unofficial/patterns/blob/master/anti_patterns/deny-warnings.md
#![deny(
bad_style,
const_err,
//dead_code,
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
//unused,
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

mod error;

pub use error::*;

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
    /// The output size of the PRF, in bits
    fn prf_output_size_in_bits(&self) -> usize;

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
    /// This function is allowed to panic if [`prf_init`] is called while already initialized
    fn prf_init(
        &mut self,
        key: &'a dyn PseudoRandomFunctionKey<KeyHandle = Self::KeyHandle>,
    ) -> Result<(), Error>;

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
    /// This function is allowed to panic if [`prf_update`] is called before [`prf_init`]
    fn prf_update(&mut self, msg: &[u8]) -> Result<(), Error>;

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
    /// This function is allowed to panic if [`prf_final`] is called before [`prf_init`]
    fn prf_final(&mut self, out: &mut [u8]) -> Result<usize, Error>;

    /// Finishes the PRF and returns the result in a `Vec<u8>`
    ///
    /// # Returns
    ///
    /// Either the result in a `Vec<u8>` or an [`Error`]
    ///
    /// # Panics
    ///
    /// This function is allowed to panic if [`prf_final_vec`] is called before [`prf_init`]
    fn prf_final_vec(&mut self) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; self.prf_output_size_in_bits() / 8];

        let size = self.prf_final(out.as_mut_slice())?;
        out.truncate(size);
        Ok(out)
    }
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

/// Performs SP800-108 Based KBKDF
pub fn kbkdf<'a, T: PseudoRandomFunction<'a>>(
    kdf_mode: &KDFMode,
    input_type: &InputType,
    key: &'a dyn PseudoRandomFunctionKey<KeyHandle = T::KeyHandle>,
    prf: &mut T,
    derived_key: &mut [u8],
) -> Result<(), Error> {
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
) -> Result<(), Error> {
    // Step 1 -> n = CEIL(L/h)
    let n = calculate_counter(derived_key.len() * 8, prf.prf_output_size_in_bits());
    let mut intermediate_key = vec![0; prf.prf_output_size_in_bits() / 8];
    let length = (derived_key.len() as u32).to_be_bytes();
    if n > 2_usize.pow(counter_mode.counter_length as u32) - 1 {
        Err(Error::InvalidDerivedKeyLen)
    } else {
        let mut result = vec![];
        for i in 1..=n {
            prf.prf_init(key)?;
            let counter = i.to_be_bytes();
            let counter = &counter[(counter.len() - counter_mode.counter_length / 8)..];
            match input_type {
                InputType::FixedInput(fixed_input) => match fixed_input.counter_location {
                    CounterLocation::NoCounter => prf.prf_update(fixed_input.fixed_input)?,
                    CounterLocation::BeforeFixedInput => {
                        prf.prf_update(counter)?;
                        prf.prf_update(fixed_input.fixed_input)?;
                    }
                    CounterLocation::MiddleOfFixedInput(position) => {
                        prf.prf_update(&fixed_input.fixed_input[..position])?;
                        prf.prf_update(counter)?;
                        prf.prf_update(&fixed_input.fixed_input[position..])?;
                    }
                    CounterLocation::AfterFixedInput => {
                        prf.prf_update(fixed_input.fixed_input)?;
                        prf.prf_update(counter)?;
                    }
                    _ => panic!(
                        "Invalid counter location for KBKDF In Counter Mode: {:?}",
                        fixed_input.counter_location
                    ),
                },
                InputType::SpecifiedInput(specified_input) => {
                    prf.prf_update(counter)?;
                    prf.prf_update(specified_input.label)?;
                    prf.prf_update(b"0")?;
                    prf.prf_update(specified_input.context)?;
                    prf.prf_update(&length)?;
                }
            }
            let _ = prf.prf_final(intermediate_key.as_mut_slice())?;
            result.extend_from_slice(intermediate_key.as_slice());
        }

        derived_key.clone_from_slice(&result[..derived_key.len()]);
        Ok(())
    }
}

fn kbkdf_double_pipeline<'a, T: PseudoRandomFunction<'a>>(
    double_feedback: &DoublePipelineIterationMode,
    input_type: &InputType,
    key: &'a dyn PseudoRandomFunctionKey<KeyHandle = T::KeyHandle>,
    prf: &mut T,
    derived_key: &mut [u8],
) -> Result<(), Error> {
    let n = calculate_counter(derived_key.len() * 8, prf.prf_output_size_in_bits());
    let mut intermediate_key = vec![0; prf.prf_output_size_in_bits() / 8];
    let length = (derived_key.len() as u32).to_be_bytes();
    if n > 2_usize.pow(32) - 1 {
        Err(Error::InvalidDerivedKeyLen)
    } else {
        let mut result = vec![];
        let mut feedback = match input_type {
            InputType::FixedInput(fixed_input) => fixed_input.fixed_input.to_vec(),
            InputType::SpecifiedInput(specified_input) => {
                let mut feedback = vec![];
                feedback.extend_from_slice(specified_input.label);
                feedback.push(0);
                feedback.extend_from_slice(specified_input.context);
                feedback.extend_from_slice(length.as_slice());
                feedback
            }
        };
        assert!(feedback.len() >= (prf.prf_output_size_in_bits() / 8));
        for i in 1..=n {
            let counter = i.to_be_bytes();
            let counter: Option<&[u8]> = match double_feedback.counter_length {
                None => None,
                Some(length) => Some(&counter[(counter.len() - length / 8)..]),
            };
            prf.prf_init(key)?;
            prf.prf_update(feedback.as_slice())?;
            let len = prf.prf_final(feedback.as_mut_slice())?;
            if feedback.len() != len {
                feedback.truncate(len);
            }
            prf.prf_init(key)?;

            match input_type {
                InputType::FixedInput(fixed_input) => {
                    match fixed_input.counter_location {
                        CounterLocation::NoCounter => {
                            prf.prf_update(feedback.as_slice())?;
                            prf.prf_update(fixed_input.fixed_input)?;
                        }
                        CounterLocation::BeforeIter => {
                            prf.prf_update(counter.expect(
                                "Counter length not provided for BeforeIter counter location",
                            ))?;
                            prf.prf_update(feedback.as_slice())?;
                            prf.prf_update(fixed_input.fixed_input)?;
                        }
                        CounterLocation::AfterFixedInput => {
                            prf.prf_update(feedback.as_slice())?;
                            prf.prf_update(fixed_input.fixed_input)?;
                            prf.prf_update(counter.expect(
                                "Counter length not provided for AfterFixedInput counter location",
                            ))?;
                        }
                        CounterLocation::AfterIter => {
                            prf.prf_update(feedback.as_slice())?;
                            prf.prf_update(counter.expect(
                                "Counter length not provided for AfterIter counter location",
                            ))?;
                            prf.prf_update(fixed_input.fixed_input)?;
                        }
                        _ => panic!(
                            "Invalid counter location for double feedback: {:?}",
                            fixed_input.counter_location
                        ),
                    }
                }
                InputType::SpecifiedInput(specified_input) => {
                    prf.prf_update(feedback.as_slice())?;
                    if let Some(counter) = counter {
                        prf.prf_update(counter)?;
                    }
                    prf.prf_update(specified_input.label)?;
                    prf.prf_update(b"0")?;
                    prf.prf_update(specified_input.context)?;
                    prf.prf_update(&length)?;
                }
            }

            if intermediate_key.is_empty() {
                intermediate_key.resize(prf.prf_output_size_in_bits() / 8, 0);
            }
            let _ = prf.prf_final(intermediate_key.as_mut_slice())?;
            result.extend_from_slice(intermediate_key.as_slice());
        }

        derived_key.clone_from_slice(&result[..derived_key.len()]);
        Ok(())
    }
}

fn kbkdf_feedback<'a, T: PseudoRandomFunction<'a>>(
    feedback_mode: &FeedbackMode,
    input_type: &InputType,
    key: &'a dyn PseudoRandomFunctionKey<KeyHandle = T::KeyHandle>,
    prf: &mut T,
    derived_key: &mut [u8],
) -> Result<(), Error> {
    let n = calculate_counter(derived_key.len() * 8, prf.prf_output_size_in_bits());
    let mut intermediate_key = match feedback_mode.iv {
        None => vec![],
        Some(iv) => iv.to_vec(),
    };
    let length = (derived_key.len() as u32).to_be_bytes();
    if n > 2_usize.pow(32) - 1 {
        Err(Error::InvalidDerivedKeyLen)
    } else {
        let mut result = vec![];
        for i in 1..=n {
            prf.prf_init(key)?;
            let counter = i.to_be_bytes();
            let counter: Option<&[u8]> = match feedback_mode.counter_length {
                None => None,
                Some(length) => Some(&counter[(counter.len() - length / 8)..]),
            };
            match input_type {
                InputType::FixedInput(fixed_input) => {
                    match fixed_input.counter_location {
                        CounterLocation::NoCounter => {
                            prf.prf_update(intermediate_key.as_slice())?;
                            prf.prf_update(fixed_input.fixed_input)?;
                        }
                        CounterLocation::BeforeIter => {
                            prf.prf_update(counter.expect(
                                "Counter length not provided for BeforeIter counter location",
                            ))?;
                            prf.prf_update(intermediate_key.as_slice())?;
                            prf.prf_update(fixed_input.fixed_input)?;
                        }
                        CounterLocation::AfterIter => {
                            prf.prf_update(intermediate_key.as_slice())?;
                            prf.prf_update(counter.expect(
                                "Counter length not provided for AfterIter counter location",
                            ))?;
                            prf.prf_update(fixed_input.fixed_input)?;
                        }
                        CounterLocation::AfterFixedInput => {
                            prf.prf_update(intermediate_key.as_slice())?;
                            prf.prf_update(fixed_input.fixed_input)?;
                            prf.prf_update(counter.expect(
                                "Counter length not provided for AfterFixedInput counter location",
                            ))?;
                        }
                        _ => panic!(
                            "Invalid counter location provided for KDF feedback mode: {:?}",
                            fixed_input.counter_location
                        ),
                    }
                }
                InputType::SpecifiedInput(specified_input) => {
                    prf.prf_update(intermediate_key.as_slice())?;
                    if let Some(counter) = counter {
                        prf.prf_update(counter)?;
                    }
                    prf.prf_update(specified_input.label)?;
                    prf.prf_update(b"0")?;
                    prf.prf_update(specified_input.context)?;
                    prf.prf_update(&length)?;
                }
            }
            if intermediate_key.is_empty() {
                intermediate_key.resize(prf.prf_output_size_in_bits() / 8, 0);
            }
            let _ = prf.prf_final(intermediate_key.as_mut_slice())?;
            result.extend_from_slice(intermediate_key.as_slice());
        }

        derived_key.clone_from_slice(&result[..derived_key.len()]);
        Ok(())
    }
}

fn calculate_counter(derived_key_len_bits: usize, prf_output_size_in_bits: usize) -> usize {
    derived_key_len_bits / prf_output_size_in_bits
        + if derived_key_len_bits % prf_output_size_in_bits != 0 {
        1
    } else {
        0
    }
}
