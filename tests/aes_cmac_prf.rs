use rust_kbkdf::{Error, PseudoRandomFunction, PseudoRandomFunctionKey};
use openssl::error::ErrorStack;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer;
use openssl::symm::Cipher;
use std::fmt::Formatter;

pub struct AesCmacKey {
    key: PKey<Private>,
}

impl AesCmacKey {
    pub fn new_from_pkey(key: PKey<Private>) -> Self {
        Self { key }
    }

    pub fn new(key: &[u8]) -> Result<Self, SSLError> {
        let cipher = match key.len() {
            16 => Cipher::aes_128_cbc(),
            24 => Cipher::aes_192_cbc(),
            32 => Cipher::aes_256_cbc(),
            _ => panic!("Invalid key length {}", key.len()),
        };
        let key = PKey::cmac(&cipher, key)?;
        Ok(Self::new_from_pkey(key))
    }
}

impl PseudoRandomFunctionKey for AesCmacKey {
    type KeyHandle = PKey<Private>;

    fn key_handle(&self) -> &Self::KeyHandle {
        &self.key
    }
}

#[derive(Default)]
pub struct AesCmac<'a> {
    signer: Option<Signer<'a>>,
}

impl AesCmac<'_> {
    pub fn new() -> Self {
        Self {
            signer: None,
        }
    }

    fn prf_update_internal(&mut self, msg: &[u8]) -> Result<(), SSLError> {
        Ok(self
            .signer
            .as_mut()
            .expect("prf_update called before prf_init")
            .update(msg)?)
    }

    fn prf_final_internal(&mut self, out: &mut [u8]) -> Result<usize, SSLError> {
        let signer = self
            .signer
            .take()
            .expect("prf_final called before prf_init");
        Ok(signer.sign(out)?)
    }
}

impl<'a> AesCmac<'a> {
    fn prf_init_internal(&mut self, key: &'a PKey<Private>) -> Result<(), SSLError> {
        assert!(self.signer.is_none());
        assert_eq!(key.id(), Id::CMAC);
        self.signer = Some(Signer::new_without_digest(key)?);
        Ok(())
    }
}

#[derive(Debug)]
pub struct SSLError {
    stack: ErrorStack,
}

impl std::fmt::Display for SSLError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.stack)
    }
}

impl std::error::Error for SSLError {}

impl From<ErrorStack> for SSLError {
    fn from(stack: ErrorStack) -> Self {
        Self { stack }
    }
}

impl From<SSLError> for Error {
    fn from(ssl_error: SSLError) -> Self {
        Self::ImplementationError(format!("{}", ssl_error.stack))
    }
}

impl<'a> PseudoRandomFunction<'a> for AesCmac<'a> {
    type KeyHandle = PKey<Private>;
    type PrfOutputSize = typenum::U16;

    fn prf_init(
        &mut self,
        key: &'a dyn PseudoRandomFunctionKey<KeyHandle = Self::KeyHandle>,
    ) -> Result<(), Error> {
        Ok(self.prf_init_internal(key.key_handle())?)
    }

    fn prf_update(&mut self, msg: &[u8]) -> Result<(), Error> {
        Ok(self.prf_update_internal(msg)?)
    }

    fn prf_final(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        Ok(self.prf_final_internal(out)?)
    }
}
