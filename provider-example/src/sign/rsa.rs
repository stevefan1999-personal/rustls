use alloc::{boxed::Box, sync::Arc};
use rsa::{
    pkcs8::{self, DecodePrivateKey},
    sha2::{Sha256, Sha384, Sha512},
    RsaPrivateKey,
};
use rustls::{
    sign::{Signer, SigningKey},
    PrivateKey, SignatureAlgorithm, SignatureScheme,
};

pub struct RsaSigningKey(RsaPrivateKey);

static ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = ALL_RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme));
        if let Some(scheme) = scheme {
            let scheme = *scheme;
            let pkey = self.0.clone();
            match scheme {
                SignatureScheme::RSA_PSS_SHA512 => Some(Box::new(super::GenericRandomizedSigner {
                    _marker: Default::default(),
                    key: Arc::new(rsa::pss::SigningKey::<Sha512>::new(pkey)),
                    scheme,
                })),
                SignatureScheme::RSA_PSS_SHA384 => Some(Box::new(super::GenericRandomizedSigner {
                    _marker: Default::default(),
                    key: Arc::new(rsa::pss::SigningKey::<Sha384>::new(pkey)),
                    scheme,
                })),
                SignatureScheme::RSA_PSS_SHA256 => Some(Box::new(super::GenericRandomizedSigner {
                    _marker: Default::default(),
                    key: Arc::new(rsa::pss::SigningKey::<Sha256>::new(pkey)),
                    scheme,
                })),
                SignatureScheme::RSA_PKCS1_SHA512 => {
                    Some(Box::new(super::GenericRandomizedSigner {
                        _marker: Default::default(),
                        key: Arc::new(rsa::pkcs1v15::SigningKey::<Sha512>::new(pkey)),
                        scheme,
                    }))
                }
                SignatureScheme::RSA_PKCS1_SHA384 => {
                    Some(Box::new(super::GenericRandomizedSigner {
                        _marker: Default::default(),
                        key: Arc::new(rsa::pkcs1v15::SigningKey::<Sha384>::new(pkey)),
                        scheme,
                    }))
                }
                SignatureScheme::RSA_PKCS1_SHA256 => {
                    Some(Box::new(super::GenericRandomizedSigner {
                        _marker: Default::default(),
                        key: Arc::new(rsa::pkcs1v15::SigningKey::<Sha256>::new(pkey)),
                        scheme,
                    }))
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl TryFrom<PrivateKey> for RsaSigningKey {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        RsaPrivateKey::from_pkcs8_der(&value.0).map(Self)
    }
}
