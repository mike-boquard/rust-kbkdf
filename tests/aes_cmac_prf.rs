use openssl::error::ErrorStack;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer;
use openssl::symm::Cipher;
use rust_kbkdf::{PseudoRandomFunction, PseudoRandomFunctionKey};

pub struct AesCmacKey {
    key: PKey<Private>,
}

impl AesCmacKey {
    pub fn new_from_pkey(key: PKey<Private>) -> Self {
        Self { key }
    }

    pub fn new(key: &[u8]) -> Result<Self, ErrorStack> {
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
        Self { signer: None }
    }

    fn prf_update_internal(&mut self, msg: &[u8]) -> Result<(), ErrorStack> {
        Ok(self
            .signer
            .as_mut()
            .expect("prf_update called before prf_init")
            .update(msg)?)
    }

    fn prf_final_internal(&mut self, out: &mut [u8]) -> Result<usize, ErrorStack> {
        let signer = self
            .signer
            .take()
            .expect("prf_final called before prf_init");
        Ok(signer.sign(out)?)
    }
}

impl<'a> AesCmac<'a> {
    fn prf_init_internal(&mut self, key: &'a PKey<Private>) -> Result<(), ErrorStack> {
        assert!(self.signer.is_none());
        assert_eq!(key.id(), Id::CMAC);
        self.signer = Some(Signer::new_without_digest(key)?);
        Ok(())
    }
}

impl<'a> PseudoRandomFunction<'a> for AesCmac<'a> {
    type KeyHandle = PKey<Private>;
    type PrfOutputSize = typenum::U16;
    type Error = ErrorStack;

    fn prf_init(
        &mut self,
        key: &'a dyn PseudoRandomFunctionKey<KeyHandle = Self::KeyHandle>,
    ) -> Result<(), Self::Error> {
        self.prf_init_internal(key.key_handle())
    }

    fn prf_update(&mut self, msg: &[u8]) -> Result<(), Self::Error> {
        self.prf_update_internal(msg)
    }

    fn prf_final(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
        self.prf_final_internal(out)
    }
}
