use crate::crypto::CryptoProvider;
use crate::rand::GetRandomFailed;
use crate::suites::SupportedCipherSuite;

pub use aws_lc_rs as lib;

// aws-lc-rs has a ring-compatible API, so we just reuse all that
// glue here.  The shared files should always use `super::lib` to access a
// ring-compatible crate.

#[path = "../ring/hash.rs"]
pub(crate) mod hash;
#[path = "../ring/hmac.rs"]
pub(crate) mod hmac;
#[path = "../ring/kx.rs"]
pub(crate) mod kx;
#[cfg(feature = "quic")]
#[path = "../ring/quic.rs"]
pub(crate) mod quic;
#[path = "../ring/ticketer.rs"]
pub(crate) mod ticketer;
#[cfg(feature = "tls12")]
#[path = "../ring/tls12.rs"]
pub(crate) mod tls12;
#[path = "../ring/tls13.rs"]
pub(crate) mod tls13;

/// Using software keys for authentication.
#[path = "../ring/sign.rs"]
pub mod sign;

/// Default crypto provider.
#[derive(Debug)]
pub struct AwsLcRs;

impl CryptoProvider for AwsLcRs {
    type KeyExchange = kx::KeyExchange;

    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        use lib::rand::SecureRandom;

        lib::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }

    fn default_cipher_suites() -> &'static [SupportedCipherSuite] {
        DEFAULT_CIPHER_SUITES
    }
}

/// The cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

/// A list of all the cipher suites supported by the rustls *ring* provider.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS1.3 suites
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS1.2 suites
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// All defined key exchange groups supported by aws-lc-rs appear in this module.
///
/// [`ALL_KX_GROUPS`] is provided as an array of all of these values.
pub mod kx_group {
    pub use super::kx::SECP256R1;
    pub use super::kx::SECP384R1;
    pub use super::kx::X25519;
}

pub use kx::{SupportedKxGroup, ALL_KX_GROUPS};
pub use ticketer::Ticketer;
