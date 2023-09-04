use alloc::{boxed::Box, sync::Arc};
use ed25519_dalek::{pkcs8, pkcs8::DecodePrivateKey};
use rustls::{
    sign::{Signer, SigningKey},
    PrivateKey, SignatureAlgorithm, SignatureScheme,
};

pub struct EddsaSigningKey<C> {
    key: Arc<C>,
    scheme: SignatureScheme,
}

impl TryFrom<PrivateKey> for EddsaSigningKey<ed25519_dalek::SigningKey> {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        let pkcs8 = ed25519_dalek::SigningKey::from_pkcs8_der(&value.0);
        pkcs8.map(|kp| Self {
            key: Arc::new(kp),
            scheme: SignatureScheme::ED25519,
        })
    }
}

impl SigningKey for EddsaSigningKey<ed25519_dalek::SigningKey> {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(super::GenericSigner {
                _marker: Default::default(),
                key: self.key.clone(),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}
